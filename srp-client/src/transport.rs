//! UDP, TCP and DNS-over-TLS transport for signed SRP updates.
//!
//! The signed wire bytes are sent unchanged on every retransmission, since a
//! fresh message ID would need a fresh signature. Responses are matched on the
//! connected socket (source address), the message ID, QR=1, the opcode and,
//! when present, the zone section. Anything else is ignored, except a response
//! whose header matches but whose body does not decode: that is reported
//! rather than waited out.
//!
//! TCP is the default: registrars may refuse SRP over UDP (sig0lease does
//! unless `allow_udp` is set). A truncated UDP response is retried over TCP.
//! TLS (RFC 7858) frames messages like TCP, inside a TLS session; see
//! [`crate::tls`].

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Edns, Header, Message, MessageParts, MessageType};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};

use crate::error::{Result, SrpError};
use crate::tls::TlsConfig;

/// Largest UDP response we accept. Responses to updates are small; this only
/// guards against oversized junk.
const MAX_UDP_RESPONSE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// DNS over TCP (RFC 7766), one connection per update.
    #[default]
    Tcp,
    /// DNS over UDP with retransmission, falling back to TCP on truncation.
    Udp,
    /// DNS-over-TLS (RFC 7858), one connection per update. Usually port 853.
    Tls,
}

/// Sends `wire` (the signed form of `request`) over `transport` and waits for
/// the matching response. `tls` is only used with [`Transport::Tls`].
pub async fn exchange(
    transport: Transport,
    server: SocketAddr,
    request: &Message,
    wire: &[u8],
    policy: RetryPolicy,
    tls: &TlsConfig,
) -> Result<Message> {
    match transport {
        Transport::Tcp => exchange_tcp(server, request, wire, policy.total).await,
        Transport::Tls => exchange_tls(server, tls, request, wire, policy.total).await,
        Transport::Udp => match exchange_udp(server, request, wire, policy).await {
            Err(SrpError::Truncated { .. }) => {
                exchange_tcp(server, request, wire, policy.total).await
            }
            other => other,
        },
    }
}

/// Retransmission schedule: `initial`, doubling up to `max`, until `total`
/// has elapsed since the first send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub initial: Duration,
    pub max: Duration,
    pub total: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(8),
            total: Duration::from_secs(30),
        }
    }
}

/// Sends `wire` (the signed form of `request`) to `server` over UDP and waits
/// for the matching response.
pub async fn exchange_udp(
    server: SocketAddr,
    request: &Message,
    wire: &[u8],
    policy: RetryPolicy,
) -> Result<Message> {
    let net_err = |source| SrpError::Network { server, source };
    let local: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(local).await.map_err(net_err)?;
    // Connecting makes the kernel drop datagrams from any other source.
    socket.connect(server).await.map_err(net_err)?;

    let deadline = Instant::now() + policy.total;
    let mut wait = policy.initial;
    let mut attempts = 0u32;
    let mut buf = vec![0u8; MAX_UDP_RESPONSE];

    while Instant::now() < deadline {
        socket.send(wire).await.map_err(net_err)?;
        attempts += 1;
        let attempt_deadline = (Instant::now() + wait).min(deadline);

        loop {
            let len = match timeout_at(attempt_deadline, socket.recv(&mut buf)).await {
                Err(_elapsed) => break,
                Ok(received) => received.map_err(net_err)?,
            };
            if let Some(response) = decode_response(server, request, &buf[..len])? {
                if response.truncated() {
                    return Err(SrpError::Truncated { server });
                }
                return Ok(response);
            }
        }
        wait = (wait * 2).min(policy.max);
    }
    Err(SrpError::Timeout { server, attempts })
}

/// Sends `wire` over a fresh TCP connection, with the 2-byte length prefix,
/// and reads responses until one matches or `timeout` expires.
pub async fn exchange_tcp(
    server: SocketAddr,
    request: &Message,
    wire: &[u8],
    timeout: Duration,
) -> Result<Message> {
    with_timeout(server, timeout, async {
        let stream = TcpStream::connect(server)
            .await
            .map_err(|source| SrpError::Network { server, source })?;
        exchange_stream(server, stream, request, wire).await
    })
    .await
}

/// Like [`exchange_tcp`], inside a TLS session set up by `tls`. The
/// handshake counts against `timeout`.
pub async fn exchange_tls(
    server: SocketAddr,
    tls: &TlsConfig,
    request: &Message,
    wire: &[u8],
    timeout: Duration,
) -> Result<Message> {
    let net_err = |source| SrpError::Network { server, source };
    with_timeout(server, timeout, async {
        let tcp = TcpStream::connect(server).await.map_err(net_err)?;
        let mut stream = tls.connect(server, tcp).await.map_err(net_err)?;
        let response = exchange_stream(server, &mut stream, request, wire).await?;
        // Send close_notify; the server may already be gone, which is fine.
        let _ = stream.shutdown().await;
        Ok(response)
    })
    .await
}

async fn with_timeout(
    server: SocketAddr,
    timeout: Duration,
    exchange: impl Future<Output = Result<Message>>,
) -> Result<Message> {
    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(SrpError::Timeout {
            server,
            attempts: 1,
        }),
    }
}

/// DNS over a byte stream (RFC 1035 section 4.2.2): sends `wire` with the
/// 2-byte length prefix, then reads messages until one matches `request`.
async fn exchange_stream(
    server: SocketAddr,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &Message,
    wire: &[u8],
) -> Result<Message> {
    let net_err = |source| SrpError::Network { server, source };
    let len = u16::try_from(wire.len()).map_err(|_| {
        net_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "message exceeds 65535 bytes",
        ))
    })?;
    // One write, so length and message go out in one segment (RFC 7766
    // section 8) and, over TLS, in one record.
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    stream.write_all(&framed).await.map_err(net_err)?;
    stream.flush().await.map_err(net_err)?;
    loop {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.map_err(net_err)?;
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut buf).await.map_err(net_err)?;
        if let Some(response) = decode_response(server, request, &buf)? {
            return Ok(response);
        }
    }
}

/// Decodes `bytes` if it is the response to `request`. Returns `None` for
/// datagrams that are not (wrong ID, not a response, other zone), and an error
/// for a response whose header matches but whose body is malformed.
fn decode_response(server: SocketAddr, request: &Message, bytes: &[u8]) -> Result<Option<Message>> {
    let Ok(header) = Header::read(&mut BinDecoder::new(bytes)) else {
        return Ok(None);
    };
    if header.id() != request.id()
        || header.message_type() != MessageType::Response
        || header.op_code() != request.op_code()
    {
        return Ok(None);
    }
    let response = Message::from_vec(bytes)
        .or_else(|strict| decode_lenient(bytes).map_err(|_| strict))
        .map_err(|e| SrpError::MalformedResponse {
            server,
            reason: e.to_string(),
        })?;
    Ok(is_response_to(request, &response).then_some(response))
}

/// Like `Message::from_vec`, but merges several OPT records into one instead
/// of rejecting the message. RFC 6891 section 6.1.1 allows only one, but
/// sig0lease before 2026-10-02 answered SRP updates with two: the request's
/// OPT echoed back, plus one carrying the granted Update Lease.
/// Options from the first OPT win; later ones only add missing codes.
fn decode_lenient(bytes: &[u8]) -> Result<Message, hickory_proto::ProtoError> {
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder)?;
    let queries = (0..header.query_count())
        .map(|_| hickory_proto::op::Query::read(&mut decoder))
        .collect::<Result<_, hickory_proto::ProtoError>>()?;
    let read = |decoder: &mut BinDecoder<'_>, count: u16| {
        Message::read_records(decoder, usize::from(count), false).map(|(records, ..)| records)
    };
    let answers = read(&mut decoder, header.answer_count())?;
    let name_servers = read(&mut decoder, header.name_server_count())?;
    let additional = read(&mut decoder, header.additional_count())?;

    let mut edns: Option<Edns> = None;
    let mut additionals = Vec::new();
    let mut sig0 = Vec::new();
    for record in additional {
        match record.record_type() {
            // An OPT without options decodes as `RData::Update0`, not `RData::OPT`.
            RecordType::OPT => match (&mut edns, record.data()) {
                (None, _) => edns = Some((&record).into()),
                (Some(edns), RData::OPT(opt)) => {
                    for (code, option) in opt.as_ref() {
                        if edns.options().get(*code).is_none() {
                            edns.options_mut().insert(option.clone());
                        }
                    }
                }
                (Some(_), _) => {}
            },
            RecordType::SIG => sig0.push(record),
            _ => additionals.push(record),
        }
    }

    let mut header = header;
    if let Some(edns) = &edns {
        header.merge_response_code(edns.rcode_high());
    }
    Ok(Message::from(MessageParts {
        header,
        queries,
        answers,
        name_servers,
        additionals,
        sig0,
        edns,
    }))
}

fn is_response_to(request: &Message, response: &Message) -> bool {
    response.id() == request.id()
        && response.message_type() == MessageType::Response
        && response.op_code() == request.op_code()
        // RFC 2136 servers echo the zone section, but it may be omitted
        // (e.g. in a FORMERR).
        && (response.queries().is_empty() || response.queries() == request.queries())
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{OpCode, Query, ResponseCode, UpdateMessage};
    use hickory_proto::rr::{Name, RecordType};

    use std::sync::Arc;

    use super::*;

    fn request() -> Message {
        let mut msg = Message::new();
        msg.set_id(0x1234).set_op_code(OpCode::Update);
        msg.add_zone(Query::query(
            Name::from_ascii("example.").unwrap(),
            RecordType::SOA,
        ));
        msg
    }

    fn response_to(request: &Message, id: u16) -> Vec<u8> {
        let mut resp = Message::new();
        resp.set_id(id)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Update)
            .set_response_code(ResponseCode::NoError);
        resp.add_queries(request.queries().to_vec());
        resp.to_vec().unwrap()
    }

    fn fast() -> RetryPolicy {
        RetryPolicy {
            initial: Duration::from_millis(50),
            max: Duration::from_millis(100),
            total: Duration::from_millis(500),
        }
    }

    #[tokio::test]
    async fn retransmits_and_skips_mismatched_ids() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let req = request();
        let wire = req.to_vec().unwrap();

        let expected = wire.clone();
        let req2 = req.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // First attempt: dropped.
            let (n, _) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected);
            // Retransmission: identical bytes. Answer with a wrong ID first.
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], expected);
            server
                .send_to(&response_to(&req2, 0x9999), peer)
                .await
                .unwrap();
            server
                .send_to(&response_to(&req2, req2.id()), peer)
                .await
                .unwrap();
        });

        let resp = exchange_udp(addr, &req, &wire, fast()).await.unwrap();
        assert_eq!(resp.id(), 0x1234);
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn times_out() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let req = request();
        let wire = req.to_vec().unwrap();
        let err = exchange_udp(addr, &req, &wire, fast()).await.unwrap_err();
        let SrpError::Timeout { attempts, .. } = err else {
            panic!("expected timeout, got {err}");
        };
        // 50 + 100 + 100 + 100 + 100 + (cut short) ms
        assert!((4..=7).contains(&attempts), "attempts = {attempts}");
        drop(server);
    }

    #[tokio::test]
    async fn tcp_exchange_skips_mismatched_ids() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let req = request();
        let wire = req.to_vec().unwrap();

        let expected = wire.clone();
        let req2 = req.clone();
        let task = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 2];
            conn.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            conn.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, expected);
            for id in [0x9999, req2.id()] {
                let resp = response_to(&req2, id);
                conn.write_all(&(resp.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                conn.write_all(&resp).await.unwrap();
            }
        });

        let resp = exchange_tcp(addr, &req, &wire, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(resp.id(), 0x1234);
        task.await.unwrap();
    }

    /// A DoT listener with a fresh self-signed certificate, like sig0lease's.
    /// It reports the SNI and ALPN it saw, and answers like the TCP test.
    async fn tls_registrar(
        alpn: Vec<Vec<u8>>,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<(Option<String>, Option<Vec<u8>>, Vec<u8>)>,
    ) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let cert = rcgen::generate_simple_self_signed(vec!["registrar.example".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        config.alpn_protocols = alpn;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = acceptor.accept(tcp).await.unwrap();
            let (_, session) = conn.get_ref();
            let sni = session.server_name().map(str::to_owned);
            let alpn = session.alpn_protocol().map(<[u8]>::to_vec);

            let mut len = [0u8; 2];
            conn.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            conn.read_exact(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf).unwrap();
            for id in [0x9999, req.id()] {
                let resp = response_to(&req, id);
                let mut framed = (resp.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&resp);
                conn.write_all(&framed).await.unwrap();
            }
            conn.flush().await.unwrap();
            // Wait for the client's close_notify.
            let mut rest = Vec::new();
            let _ = conn.read_to_end(&mut rest).await;
            (sni, alpn, buf)
        });
        (addr, task)
    }

    #[tokio::test]
    async fn tls_exchange_is_opportunistic() {
        let (addr, task) = tls_registrar(vec![b"dot".to_vec()]).await;
        let req = request();
        let wire = req.to_vec().unwrap();

        // A self-signed certificate for another name is accepted.
        let tls =
            TlsConfig::opportunistic().with_server_name("sig0lease.example".try_into().unwrap());
        let resp = exchange_tls(addr, &tls, &req, &wire, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(resp.id(), 0x1234);

        let (sni, alpn, received) = task.await.unwrap();
        assert_eq!(received, wire);
        assert_eq!(sni.as_deref(), Some("sig0lease.example"));
        assert_eq!(alpn.as_deref(), Some(b"dot".as_slice()));
    }

    #[tokio::test]
    async fn tls_without_name_sends_no_sni() {
        // A server that does not speak ALPN still works.
        let (addr, task) = tls_registrar(Vec::new()).await;
        let req = request();
        let wire = req.to_vec().unwrap();
        let resp = exchange(
            Transport::Tls,
            addr,
            &req,
            &wire,
            fast(),
            &TlsConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(resp.id(), 0x1234);
        let (sni, alpn, _) = task.await.unwrap();
        assert_eq!(sni, None);
        assert_eq!(alpn, None);
    }

    #[tokio::test]
    async fn tls_to_plain_tcp_fails_cleanly() {
        // A plain DNS/TCP listener: the handshake fails, not hangs.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = conn.read(&mut buf).await;
            // Not a TLS ServerHello.
            conn.write_all(b"\x00\x0cnot tls here").await.unwrap();
        });
        let req = request();
        let wire = req.to_vec().unwrap();
        let err = exchange_tls(
            addr,
            &TlsConfig::default(),
            &req,
            &wire,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SrpError::Network { .. }), "{err}");
    }

    /// A real NOERROR response from sig0lease (pre 2026-10-02) to an SRP
    /// update for zone `dev.zenr.io.`: two OPT records, the first carrying
    /// Update Lease LEASE=60 KEY-LEASE=120, the second only DO=1.
    const DOUBLE_OPT_RESPONSE: &str = "d03aac00000100000000000203646576047a656e7202696f0000060001\
        000029057800000000000c000200080000003c0000007800002904d0000080000000";

    #[test]
    fn decodes_response_with_two_opt_records() {
        let bytes: Vec<u8> = (0..DOUBLE_OPT_RESPONSE.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&DOUBLE_OPT_RESPONSE[i..i + 2], 16).unwrap())
            .collect();
        assert!(Message::from_vec(&bytes).is_err(), "hickory is strict");

        let mut req = Message::new();
        req.set_id(0xd03a)
            .set_op_code(hickory_proto::op::OpCode::Update);
        req.add_zone(Query::query(
            Name::from_ascii("dev.zenr.io.").unwrap(),
            RecordType::SOA,
        ));
        let server = "192.0.2.1:53".parse().unwrap();
        let resp = decode_response(server, &req, &bytes).unwrap().unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        let lease = crate::Lease::from_message(&resp).unwrap().unwrap();
        assert_eq!((lease.lease, lease.key_lease()), (60, 120));
        assert_eq!(resp.max_payload(), 1400);
        assert!(resp.additionals().is_empty());

        // Someone else's response is skipped, not an error.
        req.set_id(0x0001);
        assert!(decode_response(server, &req, &bytes).unwrap().is_none());
    }

    #[test]
    fn malformed_matching_response_is_an_error() {
        let req = request();
        let mut bytes = response_to(&req, req.id());
        bytes.truncate(bytes.len() - 3);
        let server = "192.0.2.1:53".parse().unwrap();
        assert!(matches!(
            decode_response(server, &req, &bytes),
            Err(SrpError::MalformedResponse { .. })
        ));
    }

    #[test]
    fn matching_requires_same_zone() {
        let req = request();
        let mut other = req.clone();
        other.queries_mut()[0].set_name(Name::from_ascii("other.").unwrap());
        let resp = Message::from_vec(&response_to(&other, req.id())).unwrap();
        assert!(!is_response_to(&req, &resp));
        let resp = Message::from_vec(&response_to(&req, req.id())).unwrap();
        assert!(is_response_to(&req, &resp));
    }
}
