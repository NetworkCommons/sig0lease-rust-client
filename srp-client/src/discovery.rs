//! Finding the registration domain and the SRP registrar (RFC 9665
//! section 3.1.1).
//!
//! 1. Registration domain: configured, or the default one from DNS-SD Domain
//!    Enumeration, `dr._dns-sd._udp.<domain>` PTR (RFC 6763 section 11).
//! 2. Zone apex of the registration domain, with SOA queries (RFC 8765
//!    section 6.1).
//! 3. SRV `_dnssd-srp._tcp.<name>`, or `_dnssd-srp-tls._tcp.<name>` for TLS.
//!    RFC 9665 looks only at the zone apex ([`DiscoveryMode::ApexOnly`]). The
//!    default, [`DiscoveryMode::Closest`], looks at the registration domain
//!    first and then at each parent up to the apex, as sig0lease's client
//!    does, so a registrar can serve a domain inside a zone without a zone cut
//!    (`dev.zenr.io` inside `zenr.io`). A domain with no record below the apex
//!    finds what RFC 9665 finds. A TLS search never falls back to the plain
//!    TCP record: a requester that can use TLS SHOULD NOT (section 7).
//! 4. The SRV targets, ordered by RFC 2782 (priority, then weighted random),
//!    resolved to addresses from the additional section or with AAAA/A
//!    queries. The SRV port is honored.
//!
//! Optionally, without an SRV record, the primary from the zone's SOA (MNAME,
//! port 53) is used, as for classic RFC 2136 updates.
//!
//! Queries go to a configured list of recursive resolvers, by default the
//! nameservers in `/etc/resolv.conf`, over UDP with TCP fallback. A resolver
//! that does not answer, or answers neither NOERROR nor NXDOMAIN, is skipped.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::SRV;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::ServerName;

use crate::client::Endpoint;
use crate::error::{Result, SrpError};
use crate::tls::DOT_PORT;
use crate::transport::{RetryPolicy, Transport, exchange};

/// SRV service name for SRP over UDP or TCP (RFC 9665 section 10.4).
pub const SRP_SERVICE: &str = "_dnssd-srp._tcp";
/// SRV service name for SRP over TLS.
pub const SRP_TLS_SERVICE: &str = "_dnssd-srp-tls._tcp";

const DNS_PORT: u16 = 53;
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// A stub resolver: sends recursive queries to a list of resolvers.
#[derive(Debug, Clone)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    retry: RetryPolicy,
}

impl Resolver {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            retry: RetryPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(2),
                total: Duration::from_secs(5),
            },
        }
    }

    /// The nameservers from `/etc/resolv.conf`.
    pub fn system() -> Result<Self> {
        let text = std::fs::read_to_string(RESOLV_CONF).map_err(|source| SrpError::Io {
            path: RESOLV_CONF.into(),
            source,
        })?;
        let conf = ResolvConf::parse(&text);
        if conf.nameservers.is_empty() {
            return Err(SrpError::Discovery(format!(
                "no usable nameserver in {RESOLV_CONF}"
            )));
        }
        Ok(Self::new(conf.nameservers))
    }

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// Asks each resolver in turn until one answers NOERROR or NXDOMAIN.
    pub async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message> {
        let mut request = Message::new();
        request
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        request.add_query(Query::query(name.clone(), rtype));
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        request.set_edns(edns);
        let wire = request.to_vec()?;

        let mut failures = Vec::new();
        for &server in &self.servers {
            let tls = Default::default();
            match exchange(Transport::Udp, server, &request, &wire, self.retry, &tls).await {
                Ok(response) => {
                    use hickory_proto::op::ResponseCode::{NXDomain, NoError};
                    match response.response_code() {
                        NoError | NXDomain => return Ok(response),
                        rcode => failures.push(format!("{server}: {rcode}")),
                    }
                }
                Err(e) => failures.push(e.to_string()),
            }
        }
        Err(SrpError::Discovery(format!(
            "{rtype} query for {name} failed: {}",
            if failures.is_empty() {
                "no resolvers configured".to_string()
            } else {
                failures.join("; ")
            }
        )))
    }

    /// Records of `rtype` in the answer section. CNAMEs are followed by the
    /// resolver; the owner is not checked, so the end of a chain counts.
    async fn records(&self, name: &Name, rtype: RecordType) -> Result<(Vec<Record>, Message)> {
        let response = self.query(name, rtype).await?;
        let records = response
            .answers()
            .iter()
            .filter(|r| r.record_type() == rtype)
            .cloned()
            .collect();
        Ok((records, response))
    }
}

/// The parts of `/etc/resolv.conf` discovery uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvConf {
    pub nameservers: Vec<SocketAddr>,
    /// `search` list, or `domain`: candidates for Domain Enumeration.
    pub search: Vec<Name>,
}

impl ResolvConf {
    pub fn parse(text: &str) -> Self {
        let mut conf = Self::default();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut words = line.split_whitespace();
            match words.next() {
                // Link-local addresses with a zone (`fe80::1%eth0`) do not
                // parse as IpAddr and are skipped.
                Some("nameserver") => {
                    if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok()) {
                        conf.nameservers.push(SocketAddr::new(ip, DNS_PORT));
                    }
                }
                Some("search" | "domain") => {
                    conf.search = words
                        .filter_map(|w| Name::from_ascii(w).ok())
                        .map(|mut n| {
                            n.set_fqdn(true);
                            n
                        })
                        .collect();
                }
                _ => {}
            }
        }
        conf
    }

    pub fn system() -> Result<Self> {
        let text = std::fs::read_to_string(RESOLV_CONF).map_err(|source| SrpError::Io {
            path: RESOLV_CONF.into(),
            source,
        })?;
        Ok(Self::parse(&text))
    }
}

/// Where to look for the registrar's SRV record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoveryMode {
    /// The registration domain, then each parent up to the zone apex.
    #[default]
    Closest,
    /// Only the zone apex, as RFC 9665 section 3.1.1 specifies.
    ApexOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiscoveryOptions {
    /// Look for `_dnssd-srp-tls._tcp` instead of `_dnssd-srp._tcp`.
    pub tls: bool,
    pub mode: DiscoveryMode,
    /// Without an SRV record, use the SOA MNAME on port 53. Not with `tls`.
    pub soa_fallback: bool,
}

/// How the registrar was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The SRV record set at this name.
    Srv(Name),
    /// The MNAME of the zone's SOA.
    SoaMname,
}

/// One registrar host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registrar {
    pub target: Name,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub addresses: Vec<IpAddr>,
}

/// The result of [`find_registrar`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Apex of the zone enclosing the registration domain.
    pub zone: Name,
    pub source: Source,
    /// In the order to try them. Each has at least one address.
    pub registrars: Vec<Registrar>,
}

impl Discovered {
    /// Every address of every registrar, in order, with the target as TLS
    /// server name.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.registrars
            .iter()
            .flat_map(|r| {
                let tls_name = tls_name(&r.target);
                r.addresses.iter().map(move |&ip| Endpoint {
                    addr: SocketAddr::new(ip, r.port),
                    tls_name: tls_name.clone(),
                })
            })
            .collect()
    }
}

fn tls_name(target: &Name) -> Option<ServerName<'static>> {
    let name = target.to_ascii();
    ServerName::try_from(name.trim_end_matches('.').to_owned()).ok()
}

/// Default registration domains from `dr._dns-sd._udp.<domain>` PTR records
/// (RFC 6763 section 11). Empty if there are none.
pub async fn registration_domains(resolver: &Resolver, domain: &Name) -> Result<Vec<Name>> {
    let qname = Name::from_ascii("dr._dns-sd._udp")?.append_domain(domain)?;
    let (records, _) = resolver.records(&qname, RecordType::PTR).await?;
    Ok(records
        .iter()
        .filter_map(|r| match r.data() {
            RData::PTR(ptr) => Some(ptr.0.clone()),
            _ => None,
        })
        .collect())
}

/// The apex of the zone enclosing `name` and its SOA MNAME (RFC 8765
/// section 6.1): the owner of the SOA in the answer, or in the authority
/// section of a negative answer. Without either, the parent is asked.
pub async fn zone_apex(resolver: &Resolver, name: &Name) -> Result<(Name, Name)> {
    let mut current = name.clone();
    loop {
        let response = resolver.query(&current, RecordType::SOA).await?;
        let soa = response
            .answers()
            .iter()
            .chain(response.name_servers())
            .find_map(|r| match r.data() {
                RData::SOA(soa) => Some((r.name().clone(), soa.mname().clone())),
                _ => None,
            });
        if let Some(found) = soa {
            return Ok(found);
        }
        if current.is_root() {
            return Err(SrpError::Discovery(format!("no SOA found for {name}")));
        }
        current = current.base_name();
    }
}

/// Finds the registrar for the registration domain `domain`.
pub async fn find_registrar(
    resolver: &Resolver,
    domain: &Name,
    options: DiscoveryOptions,
) -> Result<Discovered> {
    let (zone, mname) = zone_apex(resolver, domain).await?;
    let service = Name::from_ascii(if options.tls {
        SRP_TLS_SERVICE
    } else {
        SRP_SERVICE
    })?;

    let candidates = match options.mode {
        DiscoveryMode::ApexOnly => vec![zone.clone()],
        DiscoveryMode::Closest => {
            let mut names = Vec::new();
            let mut name = domain.clone();
            // Up to the apex; a domain outside its own reported zone (a
            // misbehaving resolver) stops at the root.
            loop {
                names.push(name.clone());
                if name == zone || name.is_root() {
                    break;
                }
                name = name.base_name();
            }
            names
        }
    };

    for base in &candidates {
        let qname = service.clone().append_domain(base)?;
        let (records, response) = resolver.records(&qname, RecordType::SRV).await?;
        let srvs: Vec<SRV> = records
            .iter()
            .filter_map(|r| match r.data() {
                RData::SRV(srv) => Some(srv.clone()),
                _ => None,
            })
            .collect();
        if srvs.is_empty() {
            continue;
        }
        // RFC 2782: a single SRV with target "." means "not offered here".
        if srvs.len() == 1 && srvs[0].target().is_root() {
            return Err(SrpError::Discovery(format!(
                "{qname} SRV says no registrar is offered (target \".\")"
            )));
        }
        let mut registrars = Vec::new();
        for srv in order_srv(srvs) {
            if srv.target().is_root() {
                continue;
            }
            let addresses = addresses(resolver, srv.target(), &response).await?;
            if !addresses.is_empty() {
                registrars.push(Registrar {
                    target: srv.target().clone(),
                    port: srv.port(),
                    priority: srv.priority(),
                    weight: srv.weight(),
                    addresses,
                });
            }
        }
        if registrars.is_empty() {
            return Err(SrpError::Discovery(format!(
                "no SRV target of {qname} has an address"
            )));
        }
        return Ok(Discovered {
            zone,
            source: Source::Srv(qname),
            registrars,
        });
    }

    let searched = candidates
        .iter()
        .map(|n| format!("{service}.{n}"))
        .collect::<Vec<_>>()
        .join(", ");
    if options.soa_fallback && !options.tls {
        let addresses = addresses(resolver, &mname, &Message::new()).await?;
        if !addresses.is_empty() {
            return Ok(Discovered {
                zone,
                source: Source::SoaMname,
                registrars: vec![Registrar {
                    target: mname,
                    port: DNS_PORT,
                    priority: 0,
                    weight: 0,
                    addresses,
                }],
            });
        }
    }
    Err(SrpError::Discovery(format!(
        "no SRV record found (looked for {searched})"
    )))
}

/// Default port for a registrar given without one.
pub fn default_port(tls: bool) -> u16 {
    if tls { DOT_PORT } else { DNS_PORT }
}

/// Addresses of `target`: from the additional section of `response` if it
/// has any, else from AAAA and A queries. IPv6 first.
async fn addresses(resolver: &Resolver, target: &Name, response: &Message) -> Result<Vec<IpAddr>> {
    let glue = |records: &[Record]| -> Vec<IpAddr> {
        let mut v6: Vec<IpAddr> = Vec::new();
        let mut v4: Vec<IpAddr> = Vec::new();
        for r in records {
            match r.data() {
                RData::AAAA(a) => v6.push(a.0.into()),
                RData::A(a) => v4.push(a.0.into()),
                _ => {}
            }
        }
        v6.extend(v4);
        v6
    };
    let additional: Vec<Record> = response
        .additionals()
        .iter()
        .filter(|r| r.name() == target)
        .cloned()
        .collect();
    let found = glue(&additional);
    if !found.is_empty() {
        return Ok(found);
    }
    let (mut records, _) = resolver.records(target, RecordType::AAAA).await?;
    records.extend(resolver.records(target, RecordType::A).await?.0);
    Ok(glue(&records))
}

/// RFC 2782 order: ascending priority; within a priority, weighted random
/// selection, with weight-0 records first in the running sum.
fn order_srv(mut srvs: Vec<SRV>) -> Vec<SRV> {
    srvs.sort_by_key(|s| (s.priority(), s.weight() != 0));
    let mut ordered = Vec::with_capacity(srvs.len());
    while !srvs.is_empty() {
        let priority = srvs[0].priority();
        let end = srvs
            .iter()
            .position(|s| s.priority() != priority)
            .unwrap_or(srvs.len());
        let mut group: Vec<SRV> = srvs.drain(..end).collect();
        while !group.is_empty() {
            let total: u32 = group.iter().map(|s| u32::from(s.weight())).sum();
            let pick = if total == 0 {
                0
            } else {
                let r = rand::random_range(0..=total);
                let mut sum = 0;
                group
                    .iter()
                    .position(|s| {
                        sum += u32::from(s.weight());
                        sum >= r
                    })
                    .unwrap_or(0)
            };
            ordered.push(group.remove(pick));
        }
    }
    ordered
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, AAAA, PTR, SOA};
    use tokio::net::UdpSocket;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// A recursive resolver that knows a fixed set of records.
    #[derive(Clone, Default)]
    struct Zones {
        /// Zone apexes, with their SOA MNAME.
        apexes: Vec<(Name, Name)>,
        records: Vec<Record>,
        /// Add the A/AAAA of SRV targets to the additional section.
        glue: bool,
        rcode: Option<ResponseCode>,
    }

    impl Zones {
        fn apex(mut self, apex: &str, mname: &str) -> Self {
            self.apexes.push((name(apex), name(mname)));
            self
        }
        fn record(mut self, owner: &str, rdata: RData) -> Self {
            self.records
                .push(Record::from_rdata(name(owner), 60, rdata));
            self
        }
        fn srv(self, owner: &str, priority: u16, weight: u16, port: u16, target: &str) -> Self {
            self.record(
                owner,
                RData::SRV(SRV::new(priority, weight, port, name(target))),
            )
        }
        fn a(self, owner: &str, ip: &str) -> Self {
            self.record(owner, RData::A(A(ip.parse().unwrap())))
        }
        fn aaaa(self, owner: &str, ip: &str) -> Self {
            self.record(owner, RData::AAAA(AAAA(ip.parse().unwrap())))
        }

        fn soa_record(&self, apex: &Name, mname: &Name) -> Record {
            let soa = SOA::new(mname.clone(), name("hostmaster."), 1, 3600, 600, 86400, 60);
            Record::from_rdata(apex.clone(), 60, RData::SOA(soa))
        }

        fn answer(&self, req: &Message) -> Message {
            let q = &req.queries()[0];
            let (qname, qtype) = (q.name(), q.query_type());
            let mut resp = Message::new();
            resp.set_id(req.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query);
            resp.add_query(q.clone());
            if let Some(rcode) = self.rcode {
                resp.set_response_code(rcode);
                return resp;
            }
            let Some((apex, mname)) = self
                .apexes
                .iter()
                .filter(|(apex, _)| apex.zone_of(qname))
                .max_by_key(|(apex, _)| apex.num_labels())
            else {
                resp.set_response_code(ResponseCode::Refused);
                return resp;
            };
            if qtype == RecordType::SOA && qname == apex {
                resp.add_answer(self.soa_record(apex, mname));
                return resp;
            }
            let answers: Vec<Record> = self
                .records
                .iter()
                .filter(|r| r.name() == qname && r.record_type() == qtype)
                .cloned()
                .collect();
            if answers.is_empty() {
                // NODATA for a name that exists or has descendants, else
                // NXDOMAIN; both with the SOA in the authority section.
                let exists = qname == apex || self.records.iter().any(|r| qname.zone_of(r.name()));
                if !exists {
                    resp.set_response_code(ResponseCode::NXDomain);
                }
                resp.add_name_server(self.soa_record(apex, mname));
                return resp;
            }
            if self.glue {
                for srv in answers.iter().filter_map(|r| match r.data() {
                    RData::SRV(srv) => Some(srv.target().clone()),
                    _ => None,
                }) {
                    for r in &self.records {
                        if r.name() == &srv
                            && matches!(r.record_type(), RecordType::A | RecordType::AAAA)
                        {
                            resp.add_additional(r.clone());
                        }
                    }
                }
            }
            resp.add_answers(answers);
            resp
        }
    }

    /// Serves `zones` and counts the queries per (name, type).
    async fn serve(zones: Zones) -> (SocketAddr, Arc<std::sync::Mutex<Vec<(Name, RecordType)>>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let queries = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let req = Message::from_vec(&buf[..n]).unwrap();
                let q = &req.queries()[0];
                queries
                    .lock()
                    .unwrap()
                    .push((q.name().clone(), q.query_type()));
                let resp = zones.answer(&req);
                socket.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        (addr, log)
    }

    async fn resolver(zones: Zones) -> Resolver {
        Resolver::new(vec![serve(zones).await.0]).with_retry(RetryPolicy {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(100),
            total: Duration::from_millis(300),
        })
    }

    /// Like the live setup: `dev.zenr.io` is no zone of its own, and the
    /// registrar record sits there, below the `zenr.io` apex.
    fn zenr() -> Zones {
        Zones::default()
            .apex("zenr.io.", "ns1.free2air.org.")
            .apex("free2air.org.", "ns1.free2air.org.")
            .srv(
                "_dnssd-srp._tcp.dev.zenr.io.",
                0,
                0,
                8053,
                "sig0lease.dev.zenr.io.",
            )
            .aaaa("sig0lease.dev.zenr.io.", "2001:db8::53")
            .a("sig0lease.dev.zenr.io.", "192.0.2.53")
            .a("ns1.free2air.org.", "192.0.2.1")
            .record(
                "dr._dns-sd._udp.zenr.io.",
                RData::PTR(PTR(name("dev.zenr.io."))),
            )
    }

    #[tokio::test]
    async fn apex_from_negative_answer() {
        let r = resolver(zenr()).await;
        let (apex, mname) = zone_apex(&r, &name("dev.zenr.io.")).await.unwrap();
        assert_eq!(apex, name("zenr.io."));
        assert_eq!(mname, name("ns1.free2air.org."));
        let (apex, _) = zone_apex(&r, &name("zenr.io.")).await.unwrap();
        assert_eq!(apex, name("zenr.io."));
        // A name that does not exist: NXDOMAIN, SOA in the authority section.
        let (apex, _) = zone_apex(&r, &name("nope.dev.zenr.io.")).await.unwrap();
        assert_eq!(apex, name("zenr.io."));
    }

    #[tokio::test]
    async fn closest_finds_record_below_apex() {
        let r = resolver(zenr()).await;
        let found = find_registrar(&r, &name("dev.zenr.io."), DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(found.zone, name("zenr.io."));
        assert_eq!(
            found.source,
            Source::Srv(name("_dnssd-srp._tcp.dev.zenr.io."))
        );
        let endpoints = found.endpoints();
        let addrs: Vec<String> = endpoints.iter().map(|e| e.addr.to_string()).collect();
        assert_eq!(addrs, ["[2001:db8::53]:8053", "192.0.2.53:8053"]);
        assert_eq!(
            endpoints[0].tls_name,
            Some(ServerName::try_from("sig0lease.dev.zenr.io").unwrap())
        );
    }

    #[tokio::test]
    async fn apex_only_is_rfc_strict() {
        let r = resolver(zenr()).await;
        let options = DiscoveryOptions {
            mode: DiscoveryMode::ApexOnly,
            ..Default::default()
        };
        let err = find_registrar(&r, &name("dev.zenr.io."), options)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("_dnssd-srp._tcp.zenr.io."),
            "{err}"
        );
    }

    #[tokio::test]
    async fn tls_uses_its_own_record_and_never_falls_back() {
        let zones = zenr();
        let r = resolver(zones.clone()).await;
        let tls = DiscoveryOptions {
            tls: true,
            soa_fallback: true,
            ..Default::default()
        };
        // Only the plain record exists: no fallback to it or to the MNAME.
        let err = find_registrar(&r, &name("dev.zenr.io."), tls)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("_dnssd-srp-tls._tcp.dev.zenr.io."),
            "{err}"
        );

        let zones = zones.srv(
            "_dnssd-srp-tls._tcp.zenr.io.",
            0,
            0,
            8853,
            "sig0lease.dev.zenr.io.",
        );
        let r = resolver(zones).await;
        let found = find_registrar(&r, &name("dev.zenr.io."), tls)
            .await
            .unwrap();
        assert_eq!(
            found.source,
            Source::Srv(name("_dnssd-srp-tls._tcp.zenr.io."))
        );
        assert_eq!(found.registrars[0].port, 8853);
    }

    #[tokio::test]
    async fn srv_priority_order_and_glue() {
        let mut zones = Zones::default()
            .apex("example.", "ns.example.")
            .srv("_dnssd-srp._tcp.example.", 20, 0, 53, "backup.example.")
            .srv("_dnssd-srp._tcp.example.", 10, 0, 5353, "main.example.")
            .srv("_dnssd-srp._tcp.example.", 30, 0, 53, "noaddr.example.")
            .a("main.example.", "192.0.2.10")
            .a("backup.example.", "192.0.2.20");
        zones.glue = true;
        let (addr, log) = serve(zones).await;
        let r = Resolver::new(vec![addr]);
        let found = find_registrar(&r, &name("example."), DiscoveryOptions::default())
            .await
            .unwrap();
        let targets: Vec<_> = found
            .registrars
            .iter()
            .map(|r| r.target.to_ascii())
            .collect();
        assert_eq!(
            targets,
            ["main.example.", "backup.example."],
            "no address: skipped"
        );
        assert_eq!(found.registrars[0].port, 5353);
        // Glue was used for the targets that had some: no A/AAAA queries for them.
        let log = log.lock().unwrap();
        assert!(!log.iter().any(|(n, _)| n == &name("main.example.")));
        assert!(log.iter().any(|(n, _)| n == &name("noaddr.example.")));
    }

    #[test]
    fn weighted_order_respects_priority_and_weight() {
        let srv = |p, w, t: &str| SRV::new(p, w, 53, name(t));
        let mut heavy_first = 0;
        for _ in 0..200 {
            let ordered = order_srv(vec![
                srv(1, 0, "last."),
                srv(0, 1, "light."),
                srv(0, 99, "heavy."),
            ]);
            assert_eq!(ordered[2].target(), &name("last."));
            if ordered[0].target() == &name("heavy.") {
                heavy_first += 1;
            }
        }
        assert!(heavy_first > 150, "heavy first {heavy_first} of 200");
    }

    #[tokio::test]
    async fn dot_target_means_no_registrar() {
        let zones = Zones::default().apex("example.", "ns.example.").srv(
            "_dnssd-srp._tcp.example.",
            0,
            0,
            0,
            ".",
        );
        let r = resolver(zones).await;
        let err = find_registrar(&r, &name("example."), DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no registrar is offered"), "{err}");
    }

    #[tokio::test]
    async fn soa_fallback_uses_mname() {
        let zones = Zones::default()
            .apex("example.", "ns.example.")
            .a("ns.example.", "192.0.2.1");
        let r = resolver(zones).await;
        let options = DiscoveryOptions {
            soa_fallback: true,
            ..Default::default()
        };
        let found = find_registrar(&r, &name("example."), options)
            .await
            .unwrap();
        assert_eq!(found.source, Source::SoaMname);
        assert_eq!(found.endpoints()[0].addr, "192.0.2.1:53".parse().unwrap());
        assert!(
            find_registrar(&r, &name("example."), DiscoveryOptions::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn registration_domain_from_domain_enumeration() {
        let r = resolver(zenr()).await;
        let domains = registration_domains(&r, &name("zenr.io.")).await.unwrap();
        assert_eq!(domains, [name("dev.zenr.io.")]);
        assert!(
            registration_domains(&r, &name("dev.zenr.io."))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn resolver_skips_failing_servers() {
        let mut broken = zenr();
        broken.rcode = Some(ResponseCode::ServFail);
        let (bad, _) = serve(broken).await;
        let (good, _) = serve(zenr()).await;
        let r = Resolver::new(vec![bad, good]);
        let (apex, _) = zone_apex(&r, &name("dev.zenr.io.")).await.unwrap();
        assert_eq!(apex, name("zenr.io."));

        let r = Resolver::new(vec![bad]);
        let err = zone_apex(&r, &name("dev.zenr.io.")).await.unwrap_err();
        assert!(
            err.to_string().contains("SERVFAIL") || err.to_string().contains("Server Failure"),
            "{err}"
        );
    }

    #[test]
    fn parses_resolv_conf() {
        let conf = ResolvConf::parse(
            "# comment\nnameserver 192.168.1.1\nnameserver 2620:fe::9\n\
             nameserver fe80::1%eth0\nsearch zenr.io example.org ; trailing\noptions edns0\n",
        );
        assert_eq!(
            conf.nameservers,
            [
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[2620:fe::9]:53".parse().unwrap()
            ]
        );
        assert_eq!(conf.search, [name("zenr.io."), name("example.org.")]);
    }
}
