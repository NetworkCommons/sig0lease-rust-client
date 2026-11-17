//! A long-lived registration: refresh on the granted lease, rename on
//! conflict, delete instances that were dropped.
//!
//! ```no_run
//! # async fn demo(client: srp_client::SrpClient, key: srp_client::SrpKey,
//! #               reg: srp_client::Registration) -> srp_client::Result<()> {
//! use std::time::Duration;
//! use srp_client::{Event, Session, SessionConfig};
//!
//! let mut session = Session::new(client, key, reg, SessionConfig::default());
//! let mut on_event = |event: Event<'_>| println!("{event:?}");
//! session.register(&mut on_event).await?; // fails fast, e.g. on REFUSED
//! let shutdown = tokio::time::sleep(Duration::from_secs(24 * 3600));
//! session.run(shutdown, &mut on_event).await?;
//! session.remove(false).await?;
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use hickory_proto::rr::Name;
use tokio::time::{Instant, sleep_until};

use crate::client::{Accepted, SrpClient};
use crate::error::{Result, SrpError};
use crate::key::SrpKey;
use crate::model::{Registration, ServiceInstance};

/// Refreshes never come sooner than this after an update, so a registrar
/// granting a near-zero lease cannot drive a busy loop.
pub const MIN_REFRESH_DELAY: Duration = Duration::from_secs(1);

/// Longest DNS label, in bytes.
const MAX_LABEL: usize = 63;

/// What to do when the registrar answers YXDOMAIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Report the conflict as an error.
    Fail,
    /// Find the conflicting names and rename them: the host to `host-2`,
    /// `host-3`, ..., an instance to `Name (2)`, `Name (3)`, ...
    /// Gives up after `max_renames` rounds.
    Rename { max_renames: u32 },
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub conflict: ConflictPolicy,
    /// First delay before retrying a failed refresh. It doubles after each
    /// consecutive failure, up to `backoff_max`.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            conflict: ConflictPolicy::Fail,
            backoff_min: Duration::from_secs(5),
            backoff_max: Duration::from_secs(5 * 60),
        }
    }
}

/// Progress reported by [`Session::register`] and [`Session::run`].
#[derive(Debug)]
pub enum Event<'a> {
    /// The registrar accepted an update. The next refresh is due in
    /// `refresh_in`.
    Registered {
        registration: &'a Registration,
        accepted: &'a Accepted,
        refresh_in: Duration,
    },
    /// A name conflicted and was renamed; `from` and `to` are the host or
    /// instance names.
    Renamed { from: Name, to: Name },
    /// A refresh failed with a transient error and is retried after
    /// `retry_in`.
    Retrying {
        error: &'a SrpError,
        retry_in: Duration,
    },
}

/// One host and its services, kept registered.
///
/// Every update re-sends the complete registration: SRP has no partial
/// updates. Renames are remembered by the original names, so a restarted
/// session with the same key reclaims the same renamed names in the same
/// order.
#[derive(Debug)]
pub struct Session {
    client: SrpClient,
    key: SrpKey,
    config: SessionConfig,
    /// The registration as configured, before renames.
    desired: Registration,
    /// 0 means the configured host name, otherwise the `-N` suffix.
    host_suffix: u32,
    /// `(instance, service type)` as configured → ` (N)` suffix.
    instance_suffix: HashMap<(String, String), u32>,
    /// Instances (renamed form) of the last accepted update.
    registered: Vec<ServiceInstance>,
    /// Dropped instances still to delete with the next update.
    stale: Vec<ServiceInstance>,
    refresh_at: Option<Instant>,
}

impl Session {
    pub fn new(client: SrpClient, key: SrpKey, reg: Registration, config: SessionConfig) -> Self {
        Self {
            client,
            key,
            config,
            desired: reg,
            host_suffix: 0,
            instance_suffix: HashMap::new(),
            registered: Vec::new(),
            stale: Vec::new(),
            refresh_at: None,
        }
    }

    pub fn client(&self) -> &SrpClient {
        &self.client
    }

    /// The registration as sent, with renames applied.
    pub fn registration(&self) -> Registration {
        let mut reg = self.desired.clone();
        if self.host_suffix > 0 {
            reg.host.name = suffixed_host(&reg.host.name, self.host_suffix);
        }
        for svc in &mut reg.services {
            if let Some(&n) = self.instance_suffix.get(&instance_key(svc)) {
                svc.instance = suffixed_instance(&svc.instance, n);
            }
        }
        reg
    }

    /// When the next refresh is due, if anything is registered.
    pub fn refresh_at(&self) -> Option<Instant> {
        self.refresh_at
    }

    /// Sends the registration now, renaming on conflict if configured.
    pub async fn register(&mut self, on_event: &mut impl FnMut(Event<'_>)) -> Result<Accepted> {
        let mut renames = 0;
        loop {
            let reg = self.registration();
            // RFC 9664 section 5.2: the lease runs from the moment of sending.
            let sent = Instant::now();
            let error = match self
                .client
                .register_removing(&reg, &self.stale, &self.key)
                .await
            {
                Ok(accepted) => {
                    let refresh_in = refresh_delay(accepted.lease().lease);
                    self.refresh_at = Some(sent + refresh_in);
                    self.registered = reg.services.clone();
                    self.stale.clear();
                    on_event(Event::Registered {
                        registration: &reg,
                        accepted: &accepted,
                        refresh_in,
                    });
                    return Ok(accepted);
                }
                Err(e) => e,
            };
            let SrpError::Conflict(_) = error else {
                return Err(error);
            };
            let ConflictPolicy::Rename { max_renames } = self.config.conflict else {
                return Err(error);
            };
            if renames >= max_renames {
                return Err(error);
            }
            renames += 1;
            if !self.rename_conflicting(&reg, on_event).await? {
                if self.stale.is_empty() {
                    return Err(error);
                }
                // Neither the host nor a current instance conflicts, so a
                // stale instance does: its name was taken over after our
                // claim lapsed. It is not ours to delete any more.
                self.stale.clear();
            }
        }
    }

    /// Replaces the registration and sends it. Instances that were registered
    /// before and are missing from `reg` are deleted in the same update.
    /// Renames of instances that stay are kept.
    ///
    /// The host name and zone should stay the same: records under an old
    /// host name are not removed.
    pub async fn update(
        &mut self,
        reg: Registration,
        on_event: &mut impl FnMut(Event<'_>),
    ) -> Result<Accepted> {
        self.desired = reg;
        let current = self.registration();
        let dropped: Vec<_> = self
            .registered
            .iter()
            .filter(|old| !current.services.iter().any(|new| same_instance(old, new)))
            .filter(|old| !self.stale.iter().any(|s| same_instance(old, s)))
            .cloned()
            .collect();
        self.stale.extend(dropped);
        self.register(on_event).await
    }

    /// Keeps the registration alive until `shutdown` completes: refreshes at
    /// 80-85% of each granted lease and retries transient failures with
    /// exponential backoff. Registers first if nothing is registered yet.
    ///
    /// Returns `Ok` on shutdown, which may interrupt an update in flight, and
    /// `Err` on a failure that a retry cannot fix (a conflict that is not
    /// renamed, a rejection other than SERVFAIL). The registration is left in
    /// place either way; call [`Session::remove`] to delete it.
    pub async fn run(
        &mut self,
        shutdown: impl Future<Output = ()>,
        on_event: &mut impl FnMut(Event<'_>),
    ) -> Result<()> {
        let mut shutdown = pin!(shutdown);
        let mut backoff = self.config.backoff_min;
        let mut wake = self.refresh_at.unwrap_or_else(Instant::now);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                () = sleep_until(wake) => {}
            }
            let result = tokio::select! {
                () = &mut shutdown => return Ok(()),
                result = self.register(on_event) => result,
            };
            match result {
                Ok(_) => {
                    backoff = self.config.backoff_min;
                    wake = self.refresh_at.expect("set by register");
                }
                Err(error) if error.is_transient() => {
                    on_event(Event::Retrying {
                        error: &error,
                        retry_in: backoff,
                    });
                    wake = Instant::now() + backoff;
                    backoff = (backoff * 2).min(self.config.backoff_max);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Deletes the registration (LEASE=0), including instances dropped by
    /// [`Session::update`] that were not deleted yet. With `forget_key` the
    /// name reservation is released too.
    pub async fn remove(&mut self, forget_key: bool) -> Result<Accepted> {
        let accepted = self
            .client
            .remove_with(&self.registration(), &self.stale, &self.key, forget_key)
            .await?;
        self.registered.clear();
        self.stale.clear();
        self.refresh_at = None;
        Ok(accepted)
    }

    /// Finds which names of `reg` conflict, by registering the host alone and
    /// then the host with each instance alone, and renames them. YXDOMAIN
    /// does not say which name conflicted. Reports whether anything was
    /// renamed.
    async fn rename_conflicting(
        &mut self,
        reg: &Registration,
        on_event: &mut impl FnMut(Event<'_>),
    ) -> Result<bool> {
        let mut host_only = reg.clone();
        host_only.services.clear();
        match self.client.register(&host_only, &self.key).await {
            Err(SrpError::Conflict(_)) => {
                let from = reg.host_name()?;
                self.host_suffix = next_suffix(self.host_suffix);
                let to = self.registration().host_name()?;
                on_event(Event::Renamed { from, to });
                // Probing the instances under a host name that is not ours
                // would only conflict again; the next round checks them.
                return Ok(true);
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }

        let mut renamed = false;
        for (svc, desired) in reg.services.iter().zip(&self.desired.services) {
            let mut probe = host_only.clone();
            probe.services = vec![svc.clone()];
            match self.client.register(&probe, &self.key).await {
                Err(SrpError::Conflict(_)) => {
                    let key = instance_key(desired);
                    let n = next_suffix(self.instance_suffix.get(&key).copied().unwrap_or(0));
                    self.instance_suffix.insert(key, n);
                    let mut to = desired.clone();
                    to.instance = suffixed_instance(&desired.instance, n);
                    on_event(Event::Renamed {
                        from: instance_name(svc, reg)?,
                        to: instance_name(&to, reg)?,
                    });
                    renamed = true;
                }
                Err(e) => return Err(e),
                Ok(_) => {}
            }
        }
        Ok(renamed)
    }
}

/// RFC 9664 section 5.2: refresh at 80% of the granted lease plus a random
/// 0-5%, counted from when the update was sent. At least
/// [`MIN_REFRESH_DELAY`].
pub fn refresh_delay(lease_secs: u32) -> Duration {
    let lease = Duration::from_secs(lease_secs.into());
    let jitter = lease.mul_f64(0.05 * rand::random::<f64>());
    (lease * 4 / 5 + jitter).max(MIN_REFRESH_DELAY)
}

fn next_suffix(n: u32) -> u32 {
    if n == 0 { 2 } else { n + 1 }
}

/// `printer` → `printer-2`, shortening the base to stay within one label.
fn suffixed_host(base: &str, n: u32) -> String {
    let suffix = format!("-{n}");
    let base = truncate_at_char(base, MAX_LABEL - suffix.len());
    format!("{base}{suffix}")
}

/// `My Printer` → `My Printer (2)`, shortening the base to stay within one
/// label without splitting a UTF-8 character.
fn suffixed_instance(base: &str, n: u32) -> String {
    let suffix = format!(" ({n})");
    let base = truncate_at_char(base, MAX_LABEL - suffix.len());
    format!("{base}{suffix}")
}

fn truncate_at_char(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn instance_key(svc: &ServiceInstance) -> (String, String) {
    (svc.instance.clone(), svc.service_type.clone())
}

/// Same instance name: DNS names compare ASCII case-insensitively.
fn same_instance(a: &ServiceInstance, b: &ServiceInstance) -> bool {
    a.instance.eq_ignore_ascii_case(&b.instance)
        && a.service_type
            .trim_end_matches('.')
            .eq_ignore_ascii_case(b.service_type.trim_end_matches('.'))
}

/// `<instance>.<service type>.<zone>`
fn instance_name(svc: &ServiceInstance, reg: &Registration) -> Result<Name> {
    let service = Name::from_ascii(svc.service_type.trim_end_matches('.'))
        .map_err(|e| SrpError::invalid_name(&svc.service_type, e))?;
    Ok(Name::from_labels([svc.instance.as_bytes()])
        .map_err(|e| SrpError::invalid_name(&svc.instance, e))?
        .append_domain(&service)?
        .append_domain(&reg.zone)?)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
    use hickory_proto::rr::DNSClass;
    use tokio::net::UdpSocket;
    use tokio::time::sleep;

    use super::*;
    use crate::lease::Lease;
    use crate::model::Host;
    use crate::transport::{RetryPolicy, Transport};

    type Handler = dyn Fn(usize, &Message) -> ResponseCode + Send + Sync;

    /// A registrar that answers each update with `handler(index, request)`,
    /// granting `grant` on success, and records the requests.
    async fn fake_registrar(
        grant: Lease,
        handler: Arc<Handler>,
    ) -> (SocketAddr, Arc<Mutex<Vec<Message>>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let requests = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let req = Message::from_vec(&buf[..n]).unwrap();
                let index = {
                    let mut log = requests.lock().unwrap();
                    log.push(req.clone());
                    log.len() - 1
                };
                let rcode = handler(index, &req);
                let mut resp = Message::new();
                resp.set_id(req.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(req.op_code())
                    .set_response_code(rcode);
                resp.add_queries(req.queries().to_vec());
                if rcode == ResponseCode::NoError {
                    let mut edns = Edns::new();
                    edns.options_mut().insert(grant.to_edns_option());
                    resp.set_edns(edns);
                }
                socket.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        (addr, log)
    }

    /// Answers YXDOMAIN to any update that adds records at a name in `taken`.
    fn taken(names: Vec<Name>) -> Arc<Handler> {
        Arc::new(move |_, req: &Message| {
            let conflict = req
                .name_servers()
                .iter()
                .any(|r| r.dns_class() == DNSClass::IN && names.contains(r.name()));
            if conflict {
                ResponseCode::YXDomain
            } else {
                ResponseCode::NoError
            }
        })
    }

    fn registration() -> Registration {
        let mut reg = Registration::new(Host {
            name: "printer".into(),
            addresses: vec!["2001:db8::42".parse().unwrap()],
        });
        reg.services
            .push(ServiceInstance::new("My Printer", "_ipp._tcp", 631));
        reg
    }

    fn session(server: SocketAddr, reg: Registration, conflict: ConflictPolicy) -> Session {
        let client = SrpClient::new(server)
            .with_transport(Transport::Udp)
            .with_retry(RetryPolicy {
                initial: Duration::from_millis(100),
                max: Duration::from_millis(100),
                total: Duration::from_millis(500),
            });
        let config = SessionConfig {
            conflict,
            backoff_min: Duration::from_millis(50),
            backoff_max: Duration::from_millis(200),
        };
        Session::new(client, SrpKey::generate().unwrap(), reg, config)
    }

    fn name(s: &str) -> Name {
        Name::from_utf8(s).unwrap()
    }

    fn grant() -> Lease {
        Lease::new(Duration::from_secs(600), Duration::from_secs(3600))
    }

    const RENAME: ConflictPolicy = ConflictPolicy::Rename { max_renames: 5 };

    #[tokio::test]
    async fn renames_conflicting_host() {
        let handler = taken(vec![
            name("printer.default.service.arpa."),
            name("printer-2.default.service.arpa."),
        ]);
        let (server, log) = fake_registrar(grant(), handler).await;
        let mut session = session(server, registration(), RENAME);
        let mut renames = Vec::new();
        session
            .register(&mut |e| {
                if let Event::Renamed { from, to } = e {
                    renames.push((from.to_ascii(), to.to_ascii()));
                }
            })
            .await
            .unwrap();

        let reg = session.registration();
        assert_eq!(reg.host.name, "printer-3");
        assert_eq!(reg.services[0].instance, "My Printer");
        assert_eq!(
            renames,
            [
                (
                    "printer.default.service.arpa.".into(),
                    "printer-2.default.service.arpa.".into()
                ),
                (
                    "printer-2.default.service.arpa.".into(),
                    "printer-3.default.service.arpa.".into()
                ),
            ]
        );
        // full, host probe, full, host probe, full
        assert_eq!(log.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn renames_conflicting_instance_only() {
        let mut reg = registration();
        reg.services
            .push(ServiceInstance::new("My Printer", "_http._tcp", 80));
        let taken_instance = Name::from_labels([b"My Printer".as_slice(), b"_ipp", b"_tcp"])
            .unwrap()
            .append_domain(&reg.zone)
            .unwrap();
        let (server, _) = fake_registrar(grant(), taken(vec![taken_instance])).await;
        let mut session = session(server, reg, RENAME);
        session.register(&mut |_| {}).await.unwrap();

        let reg = session.registration();
        assert_eq!(reg.host.name, "printer");
        assert_eq!(reg.services[0].instance, "My Printer (2)");
        assert_eq!(reg.services[1].instance, "My Printer");
    }

    #[tokio::test]
    async fn conflict_fails_without_rename_policy() {
        let handler = taken(vec![name("printer.default.service.arpa.")]);
        let (server, log) = fake_registrar(grant(), handler).await;
        let mut session = session(server, registration(), ConflictPolicy::Fail);
        let err = session.register(&mut |_| {}).await.unwrap_err();
        assert!(matches!(err, SrpError::Conflict(_)), "{err}");
        assert_eq!(log.lock().unwrap().len(), 1, "no probes");
    }

    #[tokio::test]
    async fn gives_up_after_max_renames() {
        // Every host name is taken.
        let handler: Arc<Handler> = Arc::new(|_, req: &Message| {
            if req
                .name_servers()
                .iter()
                .any(|r| r.dns_class() == DNSClass::IN)
            {
                ResponseCode::YXDomain
            } else {
                ResponseCode::NoError
            }
        });
        let (server, _) = fake_registrar(grant(), handler).await;
        let mut session = session(
            server,
            registration(),
            ConflictPolicy::Rename { max_renames: 2 },
        );
        let err = session.register(&mut |_| {}).await.unwrap_err();
        assert!(matches!(err, SrpError::Conflict(_)), "{err}");
        assert_eq!(session.registration().host.name, "printer-3");
    }

    #[tokio::test]
    async fn update_deletes_dropped_instances_once() {
        let ok: Arc<Handler> = Arc::new(|_, _: &Message| ResponseCode::NoError);
        let (server, log) = fake_registrar(grant(), ok).await;
        let mut session = session(server, registration(), ConflictPolicy::Fail);
        session.register(&mut |_| {}).await.unwrap();

        let mut reg = registration();
        reg.services = vec![ServiceInstance::new("My Web", "_http._tcp", 80)];
        session.update(reg.clone(), &mut |_| {}).await.unwrap();
        session.update(reg, &mut |_| {}).await.unwrap();

        let deletes = |msg: &Message| -> Vec<String> {
            msg.name_servers()
                .iter()
                .filter(|r| r.dns_class() == DNSClass::NONE)
                .map(|r| r.name().to_ascii())
                .collect()
        };
        let log = log.lock().unwrap();
        assert!(deletes(&log[0]).is_empty());
        assert_eq!(deletes(&log[1]), ["_ipp._tcp.default.service.arpa."]);
        assert!(deletes(&log[2]).is_empty(), "already deleted");
    }

    #[tokio::test]
    async fn run_refreshes_and_retries_transient_errors() {
        // The second update fails once with SERVFAIL.
        let handler: Arc<Handler> = Arc::new(|i, _: &Message| {
            if i == 1 {
                ResponseCode::ServFail
            } else {
                ResponseCode::NoError
            }
        });
        // A 1 s lease is refreshed after MIN_REFRESH_DELAY.
        let lease = Lease::new(Duration::from_secs(1), Duration::from_secs(60));
        let (server, log) = fake_registrar(lease, handler).await;
        let mut session = session(server, registration(), ConflictPolicy::Fail);

        let started = Instant::now();
        let mut events = Vec::new();
        let count = log.clone();
        let shutdown = async move {
            while count.lock().unwrap().len() < 3 {
                sleep(Duration::from_millis(10)).await;
            }
            // Let the third response arrive; the next refresh is 1 s away.
            sleep(Duration::from_millis(300)).await;
        };
        session
            .run(shutdown, &mut |e| {
                events.push(match e {
                    Event::Registered { refresh_in, .. } => format!("ok {}", refresh_in.as_secs()),
                    Event::Retrying { retry_in, .. } => format!("retry {}", retry_in.as_millis()),
                    Event::Renamed { .. } => "renamed".into(),
                })
            })
            .await
            .unwrap();

        // Registered at once, the refresh after 1 s fails, the retry 50 ms
        // later succeeds.
        assert_eq!(events, ["ok 1", "retry 50", "ok 1"]);
        assert!(started.elapsed() >= MIN_REFRESH_DELAY);
        assert_eq!(log.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn run_stops_on_permanent_error() {
        let handler: Arc<Handler> = Arc::new(|_, _: &Message| ResponseCode::Refused);
        let (server, _) = fake_registrar(grant(), handler).await;
        let mut session = session(server, registration(), ConflictPolicy::Fail);
        let err = session
            .run(std::future::pending(), &mut |_| {})
            .await
            .unwrap_err();
        assert!(!err.is_transient(), "{err}");
    }

    #[test]
    fn refresh_delay_follows_rfc9664() {
        for _ in 0..100 {
            let d = refresh_delay(1000);
            assert!(d >= Duration::from_secs(800) && d <= Duration::from_secs(850));
        }
        assert_eq!(refresh_delay(0), MIN_REFRESH_DELAY);
    }

    #[test]
    fn suffixes_stay_within_a_label() {
        assert_eq!(suffixed_host("printer", 2), "printer-2");
        assert_eq!(suffixed_instance("My Printer", 3), "My Printer (3)");

        let long = "a".repeat(63);
        assert_eq!(suffixed_host(&long, 12).len(), 63);
        assert!(suffixed_host(&long, 12).ends_with("a-12"));

        // 31 two-byte characters: cut before a character, not inside one.
        let wide = "ä".repeat(31);
        let renamed = suffixed_instance(&wide, 2);
        assert!(renamed.len() <= 63);
        assert!(renamed.ends_with("ä (2)"));
    }
}
