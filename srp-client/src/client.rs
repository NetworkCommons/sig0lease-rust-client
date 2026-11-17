//! One-shot register and remove against a registrar, configured or
//! discovered. With several registrar addresses, an update that cannot reach
//! one (network error, timeout) is sent to the next; the one that answered is
//! used first from then on.
//!
//! [`Session`](crate::session::Session) builds the refresh loop and conflict
//! renaming on top of these.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;

use hickory_proto::op::{Message, ResponseCode};

use crate::error::{Result, SrpError};
use crate::key::SrpKey;
use crate::lease::Lease;
use crate::message::{UpdateKind, signed_update_removing};
use crate::model::{Registration, ServiceInstance};
use crate::tls::TlsConfig;
use crate::transport::{RetryPolicy, Transport, exchange};

/// Outcome of an accepted update.
#[derive(Debug, Clone)]
pub struct Accepted {
    /// The lease that was requested.
    pub requested: Lease,
    /// The lease granted by the registrar, if it returned an Update Lease
    /// option. RFC 9664 requires it, but older servers may omit it.
    pub granted: Option<Lease>,
    /// The full response, for diagnostics.
    pub response: Message,
    /// The registrar address that answered.
    pub server: SocketAddr,
}

impl Accepted {
    /// The lease in effect: the granted one, else the requested one.
    pub fn lease(&self) -> Lease {
        self.granted.unwrap_or(self.requested)
    }
}

/// One address of a registrar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: SocketAddr,
    /// TLS server name (SNI) for this address, e.g. the SRV target it was
    /// found under. Without it, the name in the client's [`TlsConfig`] is
    /// used, if any.
    pub tls_name: Option<ServerName<'static>>,
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            tls_name: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SrpClient {
    /// Never empty.
    servers: Arc<[Endpoint]>,
    /// Index into `servers` of the one to try first; shared by clones.
    current: Arc<AtomicUsize>,
    transport: Transport,
    retry: RetryPolicy,
    tls: TlsConfig,
}

impl SrpClient {
    pub fn new(server: impl Into<Endpoint>) -> Self {
        Self::with_servers(vec![server.into()]).expect("one server")
    }

    /// A client for several addresses, tried in order. `None` if `servers`
    /// is empty.
    pub fn with_servers(servers: Vec<Endpoint>) -> Option<Self> {
        if servers.is_empty() {
            return None;
        }
        Some(Self {
            servers: servers.into(),
            current: Arc::new(AtomicUsize::new(0)),
            transport: Transport::default(),
            retry: RetryPolicy::default(),
            tls: TlsConfig::default(),
        })
    }

    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// TLS settings for [`Transport::Tls`]. The default is opportunistic
    /// privacy, see [`crate::tls`].
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// The registrar address used first: the one that answered last.
    pub fn server(&self) -> SocketAddr {
        self.servers[self.current.load(Ordering::Relaxed)].addr
    }

    pub fn servers(&self) -> &[Endpoint] {
        &self.servers
    }

    /// Registers (or refreshes) `reg`, signed with `key`.
    pub async fn register(&self, reg: &Registration, key: &SrpKey) -> Result<Accepted> {
        self.send(reg, &[], key, UpdateKind::Register).await
    }

    /// Registers `reg` and, in the same update, deletes the `stale` instances
    /// that an earlier registration contained and `reg` no longer does.
    pub async fn register_removing(
        &self,
        reg: &Registration,
        stale: &[ServiceInstance],
        key: &SrpKey,
    ) -> Result<Accepted> {
        self.send(reg, stale, key, UpdateKind::Register).await
    }

    /// Removes the records of `reg`. With `forget_key` the name reservation is
    /// released too, so another key may claim the name afterwards.
    pub async fn remove(
        &self,
        reg: &Registration,
        key: &SrpKey,
        forget_key: bool,
    ) -> Result<Accepted> {
        self.send(reg, &[], key, UpdateKind::Remove { forget_key })
            .await
    }

    /// Removes `reg` together with `stale` instances left from an earlier
    /// registration.
    pub async fn remove_with(
        &self,
        reg: &Registration,
        stale: &[ServiceInstance],
        key: &SrpKey,
        forget_key: bool,
    ) -> Result<Accepted> {
        self.send(reg, stale, key, UpdateKind::Remove { forget_key })
            .await
    }

    async fn send(
        &self,
        reg: &Registration,
        stale: &[ServiceInstance],
        key: &SrpKey,
        kind: UpdateKind,
    ) -> Result<Accepted> {
        let (request, wire) = signed_update_removing(reg, stale, key, kind, unix_now())?;
        let (response, server) = self.exchange(&request, &wire).await?;
        check_rcode(reg, response.response_code())?;
        let requested = Lease::from_message(&request).expect("update carries a lease")?;
        let granted = Lease::from_message(&response).transpose()?;
        Ok(Accepted {
            requested,
            granted,
            response,
            server,
        })
    }
}

impl SrpClient {
    /// Sends the same signed bytes to each server in turn, starting with the
    /// current one, until one answers.
    async fn exchange(&self, request: &Message, wire: &[u8]) -> Result<(Message, SocketAddr)> {
        let start = self.current.load(Ordering::Relaxed);
        let count = self.servers.len();
        let mut last_error = None;
        for index in (0..count).map(|i| (start + i) % count) {
            let endpoint = &self.servers[index];
            let tls = match &endpoint.tls_name {
                Some(name) => self.tls.clone().with_server_name(name.clone()),
                None => self.tls.clone(),
            };
            let result = exchange(
                self.transport,
                endpoint.addr,
                request,
                wire,
                self.retry,
                &tls,
            )
            .await;
            match result {
                Ok(response) => {
                    self.current.store(index, Ordering::Relaxed);
                    return Ok((response, endpoint.addr));
                }
                Err(e @ (SrpError::Network { .. } | SrpError::Timeout { .. })) => {
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_error.expect("at least one server"))
    }
}

fn check_rcode(reg: &Registration, rcode: ResponseCode) -> Result<()> {
    let hint = match rcode {
        ResponseCode::NoError => return Ok(()),
        ResponseCode::YXDomain => {
            let name = reg
                .host_name()
                .map(|n| n.to_ascii())
                .unwrap_or_else(|_| reg.host.name.clone());
            return Err(SrpError::Conflict(name));
        }
        ResponseCode::FormErr => Some("the server may not support SRP or the Update Lease option"),
        ResponseCode::Refused => Some("zone not served or refused by policy"),
        ResponseCode::NotAuth => Some("server is not authoritative for the zone"),
        ResponseCode::NotZone => Some("a name is outside the zone"),
        ResponseCode::NotImp => Some("the server does not implement DNS UPDATE"),
        ResponseCode::ServFail => Some("server failure, retry later"),
        ResponseCode::BADSIG | ResponseCode::BADKEY | ResponseCode::BADTIME => {
            Some("SIG(0) was not accepted; check the clock")
        }
        _ => None,
    };
    Err(SrpError::Rejected { rcode, hint })
}

/// Current time for SIG(0) inception/expiration.
pub fn unix_now() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    // SIG(0) times are 32-bit serial numbers (RFC 1982), wrapping is intended.
    secs as u32
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::op::{Edns, MessageType};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::model::Host;
    use crate::transport::RetryPolicy;

    /// A minimal registrar: answers each update with `rcode` and, optionally,
    /// a granted lease.
    /// (UDP only; the client under test is switched to UDP.)
    async fn fake_registrar(rcode: ResponseCode, grant: Option<Lease>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let req = Message::from_vec(&buf[..n]).unwrap();
                assert_eq!(req.sig0().len(), 1);
                let mut resp = Message::new();
                resp.set_id(req.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(req.op_code())
                    .set_response_code(rcode);
                resp.add_queries(req.queries().to_vec());
                if let Some(lease) = grant {
                    let mut edns = Edns::new();
                    edns.options_mut().insert(lease.to_edns_option());
                    resp.set_edns(edns);
                }
                socket.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        addr
    }

    fn client(server: SocketAddr) -> SrpClient {
        SrpClient::new(server).with_transport(Transport::Udp)
    }

    fn registration() -> Registration {
        Registration::new(Host {
            name: "printer-42".into(),
            addresses: vec!["2001:db8::42".parse().unwrap()],
        })
    }

    #[tokio::test]
    async fn register_reports_granted_lease() {
        let grant = Lease::new(Duration::from_secs(600), Duration::from_secs(3600));
        let server = fake_registrar(ResponseCode::NoError, Some(grant)).await;
        let key = SrpKey::generate().unwrap();
        let accepted = client(server)
            .register(&registration(), &key)
            .await
            .unwrap();
        assert_eq!(accepted.granted, Some(grant));
        assert_eq!(accepted.lease(), grant);
        assert_eq!(accepted.requested.lease, 7200);
    }

    #[tokio::test]
    async fn missing_grant_falls_back_to_requested() {
        let server = fake_registrar(ResponseCode::NoError, None).await;
        let key = SrpKey::generate().unwrap();
        let accepted = client(server)
            .remove(&registration(), &key, true)
            .await
            .unwrap();
        assert_eq!(accepted.granted, None);
        assert_eq!(accepted.lease(), Lease::remove(Duration::ZERO, true));
    }

    #[tokio::test]
    async fn yxdomain_is_a_conflict() {
        let server = fake_registrar(ResponseCode::YXDomain, None).await;
        let key = SrpKey::generate().unwrap();
        let err = client(server)
            .register(&registration(), &key)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SrpError::Conflict(ref n) if n == "printer-42.default.service.arpa.")
        );
    }

    #[tokio::test]
    async fn fails_over_to_the_next_server_and_stays_there() {
        // A closed port: the UDP send succeeds, the ICMP error or the timeout
        // makes it fail. Use a short retry so the test is quick.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let live = fake_registrar(ResponseCode::NoError, None).await;
        let client = SrpClient::with_servers(vec![dead_addr.into(), live.into()])
            .unwrap()
            .with_transport(Transport::Udp)
            .with_retry(RetryPolicy {
                initial: Duration::from_millis(50),
                max: Duration::from_millis(50),
                total: Duration::from_millis(200),
            });
        assert_eq!(client.server(), dead_addr);
        let key = SrpKey::generate().unwrap();
        client.register(&registration(), &key).await.unwrap();
        assert_eq!(client.server(), live);
        // Clones share the choice.
        assert_eq!(client.clone().server(), live);
    }

    #[tokio::test]
    async fn refused_is_rejected() {
        let server = fake_registrar(ResponseCode::Refused, None).await;
        let key = SrpKey::generate().unwrap();
        let err = client(server)
            .register(&registration(), &key)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SrpError::Rejected {
                rcode: ResponseCode::Refused,
                ..
            }
        ));
    }
}
