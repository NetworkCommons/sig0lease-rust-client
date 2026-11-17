//! `srp`: command line client for DNS-SD Service Registration Protocol.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record};
use srp_client::client::unix_now;
use srp_client::discovery::{self, Discovered, ResolvConf, Source};
use srp_client::model::{self, DEFAULT_ZONE};
use srp_client::{
    Accepted, ConflictPolicy, DiscoveryMode, DiscoveryOptions, Event, Host, KeyStore, Lease,
    Registration, Resolver, ServiceInstance, Session, SessionConfig, SrpClient, TlsConfig,
    Transport, UpdateKind, bindkey,
};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    version,
    about = "DNS-SD Service Registration Protocol (RFC 9665) client"
)]
struct Cli {
    /// Directory holding the host keys.
    #[arg(long, global = true, default_value = "keystore")]
    keystore: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate and store the key for a host name.
    Keygen {
        #[command(flatten)]
        host: HostArgs,
        /// Replace an existing key. This gives up the claim on the name.
        #[arg(long)]
        force: bool,
    },
    /// Register (or refresh) a host and its service with a registrar.
    Register {
        #[command(flatten)]
        host: HostArgs,
        #[command(flatten)]
        reg: RegistrationArgs,
        #[command(flatten)]
        server: ServerArgs,
        /// Keep running: refresh before the granted lease runs out, and
        /// remove the registration on SIGINT/SIGTERM.
        #[arg(long)]
        daemon: bool,
        /// On a name conflict, rename the host (`host-2`, ...) or the
        /// instance (`Name (2)`, ...) and retry, up to this many times.
        #[arg(long, value_name = "N", num_args = 0..=1, default_missing_value = "5")]
        rename: Option<u32>,
    },
    /// Remove a registration (LEASE=0). Pass the same services as when
    /// registering, so their instance names are deleted too.
    Remove {
        #[command(flatten)]
        host: HostArgs,
        #[command(flatten)]
        reg: RegistrationArgs,
        #[command(flatten)]
        server: ServerArgs,
        /// Also release the name reservation (KEY-LEASE=0).
        #[arg(long)]
        forget_key: bool,
    },
    /// Find the registration domain and the registrar, and print what was
    /// found, without registering anything.
    Discover {
        #[command(flatten)]
        zone: ZoneArgs,
        #[command(flatten)]
        discovery: DiscoveryArgs,
    },
    /// Import a BIND key pair (`K<name>+013+<tag>.key` and `.private`, as
    /// made by `dnssec-keygen -a ECDSAP256SHA256 -T KEY -n HOST` or
    /// sig0namectl) into the keystore. PATH is either file.
    ImportKey {
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Replace an existing key for the same name.
        #[arg(long)]
        force: bool,
    },
    /// Write the key of a host as a BIND key pair, for `nsupdate -k` or
    /// sig0namectl.
    ExportKey {
        #[command(flatten)]
        host: HostArgs,
        /// Directory to write the two files to.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Build and sign an SRP update and print it, without sending it.
    Dump {
        #[command(flatten)]
        host: HostArgs,
        #[command(flatten)]
        reg: RegistrationArgs,
        /// Build a removal (LEASE=0) instead of a registration.
        #[arg(long)]
        remove: bool,
        /// With --remove: also release the name reservation (KEY-LEASE=0).
        #[arg(long, requires = "remove")]
        forget_key: bool,
        /// Also print a hex dump of the wire bytes.
        #[arg(long)]
        hex: bool,
        /// Write the raw wire bytes to this file.
        #[arg(long, value_name = "FILE")]
        wire: Option<PathBuf>,
    },
}

#[derive(Args)]
struct HostArgs {
    /// Host label, e.g. `printer-42`.
    #[arg(long)]
    host: String,
    #[command(flatten)]
    zone: ZoneArgs,
}

#[derive(Args)]
struct ZoneArgs {
    /// Registration domain [default: default.service.arpa., or discovered
    /// with --domain].
    #[arg(long)]
    zone: Option<String>,
    /// Discover the registration domain from `dr._dns-sd._udp.<DOMAIN>`
    /// (RFC 6763 section 11). Without a value, the search domains of
    /// /etc/resolv.conf are tried.
    #[arg(
        long,
        conflicts_with = "zone",
        value_name = "DOMAIN",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    domain: Option<String>,
    /// Recursive resolver for discovery, `IP` or `IP:PORT` (repeatable)
    /// [default: the nameservers of /etc/resolv.conf].
    #[arg(long = "resolver", value_name = "IP[:PORT]")]
    resolvers: Vec<String>,
}

impl ZoneArgs {
    fn resolver(&self) -> CliResult<Resolver> {
        if self.resolvers.is_empty() {
            return Ok(Resolver::system()?);
        }
        let servers = self
            .resolvers
            .iter()
            .map(|r| {
                r.parse::<SocketAddr>()
                    .or_else(|_| r.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                    .map_err(|_| format!("--resolver {r:?}: expected IP or IP:PORT"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Resolver::new(servers))
    }

    /// The registration domain: --zone, discovered with --domain, or the
    /// default. Reports a discovered one on stderr.
    async fn zone(&self) -> CliResult<Name> {
        if let Some(zone) = &self.zone {
            return Ok(model::parse_zone(zone)?);
        }
        let Some(domain) = &self.domain else {
            return Ok(model::parse_zone(DEFAULT_ZONE)?);
        };
        let resolver = self.resolver()?;
        let browse = if domain.is_empty() {
            let search = ResolvConf::system()?.search;
            if search.is_empty() {
                return Err(
                    "--domain without a value needs a search domain in /etc/resolv.conf".into(),
                );
            }
            search
        } else {
            vec![model::parse_zone(domain)?]
        };
        for browse in &browse {
            if let Some(zone) = discovery::registration_domains(&resolver, browse)
                .await?
                .into_iter()
                .next()
            {
                eprintln!(
                    "registration domain {} (from dr._dns-sd._udp.{})",
                    present_name(&zone),
                    present_name(browse)
                );
                return Ok(zone);
            }
        }
        let tried: Vec<_> = browse.iter().map(present_name).collect();
        Err(format!(
            "no default registration domain (dr._dns-sd._udp PTR) under {}; use --zone",
            tried.join(", ")
        )
        .into())
    }
}

#[derive(Args)]
struct DiscoveryArgs {
    /// Look for `_dnssd-srp-tls._tcp` (DNS-over-TLS) instead of
    /// `_dnssd-srp._tcp`.
    #[arg(long)]
    tls: bool,
    /// Look for the registrar's SRV record only at the zone apex, as RFC 9665
    /// specifies, not also at the registration domain and its parents.
    #[arg(long)]
    apex_only: bool,
    /// Without an SRV record, send updates to the zone's primary (SOA
    /// MNAME, port 53). Not with --tls.
    #[arg(long, conflicts_with = "tls")]
    soa_fallback: bool,
}

impl DiscoveryArgs {
    fn options(&self) -> DiscoveryOptions {
        DiscoveryOptions {
            tls: self.tls,
            mode: if self.apex_only {
                DiscoveryMode::ApexOnly
            } else {
                DiscoveryMode::Closest
            },
            soa_fallback: self.soa_fallback,
        }
    }
}

#[derive(Args)]
struct ServerArgs {
    /// Registrar as `IP`, `IP:PORT`, `[IPv6]:PORT`, `HOST` or `HOST:PORT`
    /// (default port 53, or 853 with --tls). Without it, the registrar is
    /// discovered from the registration domain's `_dnssd-srp._tcp` (or with
    /// --tls `_dnssd-srp-tls._tcp`) SRV record.
    #[arg(long)]
    server: Option<String>,
    /// Send over UDP (with TCP fallback on truncation) instead of TCP.
    #[arg(long, conflicts_with = "tls")]
    udp: bool,
    /// Send over DNS-over-TLS (RFC 7858). Opportunistic, as RFC 9665
    /// section 7 specifies: encrypted, but the registrar's certificate is not
    /// checked. A HOST in --server, or the discovered SRV target, is sent as
    /// SNI.
    #[arg(long)]
    tls: bool,
    /// With discovery: look for the SRV record only at the zone apex.
    #[arg(long, conflicts_with = "server")]
    apex_only: bool,
    /// With discovery: without an SRV record, use the SOA MNAME (port 53).
    #[arg(long, conflicts_with_all = ["server", "tls"])]
    soa_fallback: bool,
    /// Print the response.
    #[arg(long, short)]
    verbose: bool,
}

impl ServerArgs {
    /// A client for --server, or for the registrar discovered for `zone`.
    async fn client(&self, zone: &Name, zone_args: &ZoneArgs) -> CliResult<SrpClient> {
        let transport = if self.tls {
            Transport::Tls
        } else if self.udp {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        let default_port = discovery::default_port(self.tls);

        let Some(server) = &self.server else {
            if zone == &model::parse_zone(DEFAULT_ZONE)? {
                return Err(format!(
                    "{DEFAULT_ZONE} has no discoverable registrar (RFC 9665 section 3.1.2): \
                     give --server, or --zone/--domain for discovery"
                )
                .into());
            }
            let discovery = DiscoveryArgs {
                tls: self.tls,
                apex_only: self.apex_only,
                soa_fallback: self.soa_fallback,
            };
            let found =
                discovery::find_registrar(&zone_args.resolver()?, zone, discovery.options())
                    .await?;
            eprintln!("{}", describe_discovered(&found));
            let client = SrpClient::with_servers(found.endpoints()).expect("discovery found one");
            return Ok(client.with_transport(transport));
        };

        let (addr, host) = resolve_server(server, default_port).await?;
        let mut client = SrpClient::new(addr).with_transport(transport);
        if let Some(host) = host {
            let name = rustls_pki_types::ServerName::try_from(host)
                .map_err(|e| format!("{e}: not usable as TLS server name"))?;
            client = client.with_tls(TlsConfig::default().with_server_name(name));
        }
        Ok(client)
    }
}

/// One line: `registrar a.example.:8053 (via _dnssd-srp._tcp.example. SRV)`,
/// plus the other candidates.
fn describe_discovered(found: &Discovered) -> String {
    let via = match &found.source {
        Source::Srv(name) => format!("{} SRV", present_name(name)),
        Source::SoaMname => format!("SOA MNAME of {}", present_name(&found.zone)),
    };
    let targets: Vec<String> = found
        .registrars
        .iter()
        .map(|r| format!("{}:{}", present_name(&r.target), r.port))
        .collect();
    format!("registrar {} (via {via})", targets.join(", "))
}

#[derive(Args)]
struct RegistrationArgs {
    /// Host address to register (repeatable).
    #[arg(long = "addr", value_name = "IP")]
    addresses: Vec<IpAddr>,
    /// Service type, e.g. `_ipp._tcp`.
    #[arg(long, requires_all = ["instance", "port"])]
    service: Option<String>,
    /// Service instance name, e.g. `My Printer`.
    #[arg(long, requires = "service")]
    instance: Option<String>,
    #[arg(long, requires = "service")]
    port: Option<u16>,
    /// Subtype label, e.g. `_universal` (repeatable).
    #[arg(long = "subtype", requires = "service")]
    subtypes: Vec<String>,
    /// TXT entry, e.g. `rp=ipp/print` (repeatable).
    #[arg(long = "txt", requires = "service")]
    txt: Vec<String>,
    #[arg(long, default_value_t = 0, requires = "service")]
    priority: u16,
    #[arg(long, default_value_t = 0, requires = "service")]
    weight: u16,
    /// Lease in seconds.
    #[arg(long, default_value_t = model::DEFAULT_LEASE.as_secs())]
    lease: u64,
    /// KEY lease in seconds.
    #[arg(long, default_value_t = model::DEFAULT_KEY_LEASE.as_secs())]
    key_lease: u64,
    /// Record TTL in seconds (capped at the lease).
    #[arg(long, default_value_t = model::DEFAULT_TTL.as_secs())]
    ttl: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("srp: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> CliResult<()> {
    let store = KeyStore::new(cli.keystore);
    match cli.command {
        Command::Keygen { host, force } => {
            let name = model::host_name(&host.host, &host.zone.zone().await?)?;
            let (key, path) = store.generate(&name, force)?;
            let tag = key.signer(name.clone())?.calculate_key_tag()?;
            println!("generated ECDSAP256SHA256 key for {}", present_name(&name));
            println!("key tag: {tag}");
            println!("stored:  {}", path.display());
        }
        Command::Register {
            host,
            reg,
            server,
            daemon,
            rename,
        } => {
            let registration = registration(&host, reg).await?;
            let key = store.load(&registration.host_name()?)?;
            let client = server.client(&registration.zone, &host.zone).await?;
            let config = SessionConfig {
                conflict: match rename {
                    Some(max_renames) => ConflictPolicy::Rename { max_renames },
                    None => ConflictPolicy::Fail,
                },
                ..SessionConfig::default()
            };
            let mut session = Session::new(client, key, registration, config);
            let mut events = EventPrinter {
                verbose: server.verbose,
                daemon,
                updates: 0,
            };
            let mut on_event = |e: Event<'_>| events.print(e);
            session.register(&mut on_event).await?;
            if daemon {
                session.run(shutdown_signal(), &mut on_event).await?;
                let accepted = session.remove(false).await?;
                report(
                    "removed",
                    &session.registration(),
                    &accepted,
                    server.verbose,
                )?;
            }
        }
        Command::Remove {
            host,
            reg,
            server,
            forget_key,
        } => {
            let registration = registration(&host, reg).await?;
            let key = store.load(&registration.host_name()?)?;
            let client = server.client(&registration.zone, &host.zone).await?;
            let accepted = client.remove(&registration, &key, forget_key).await?;
            report("removed", &registration, &accepted, server.verbose)?;
        }
        Command::Discover { zone, discovery } => {
            let resolver = zone.resolver()?;
            let resolvers: Vec<_> = resolver.servers().iter().map(|s| s.to_string()).collect();
            println!("resolvers:           {}", resolvers.join(", "));
            let domain = zone.zone().await?;
            println!("registration domain: {}", present_name(&domain));
            let (apex, mname) = discovery::zone_apex(&resolver, &domain).await?;
            println!(
                "zone apex:           {} (primary {})",
                present_name(&apex),
                present_name(&mname)
            );
            let found = discovery::find_registrar(&resolver, &domain, discovery.options()).await?;
            match &found.source {
                Source::Srv(name) => println!("found:               {} SRV", present_name(name)),
                Source::SoaMname => println!("found:               SOA MNAME (no SRV record)"),
            }
            for r in &found.registrars {
                let addrs: Vec<_> = r.addresses.iter().map(|a| a.to_string()).collect();
                println!(
                    "registrar:           {}:{} priority {} weight {} [{}]",
                    present_name(&r.target),
                    r.port,
                    r.priority,
                    r.weight,
                    addrs.join(", ")
                );
            }
        }
        Command::ImportKey { path, force } => {
            let (name, key) = bindkey::read(&path)?;
            let stored = store.store(&name, &key, force)?;
            let tag = key.signer(name.clone())?.calculate_key_tag()?;
            println!("imported ECDSAP256SHA256 key for {}", present_name(&name));
            println!("key tag: {tag} (as published by SRP, flags 0x0201)");
            println!("stored:  {}", stored.display());
        }
        Command::ExportKey { host, dir } => {
            let name = model::host_name(&host.host, &host.zone.zone().await?)?;
            let key = store.load(&name)?;
            let files = bindkey::export(&name, &key)?;
            let (key_path, private_path) = files.write(&dir)?;
            println!("exported key for {}", present_name(&name));
            println!("public:  {}", key_path.display());
            println!("private: {}", private_path.display());
        }
        Command::Dump {
            host,
            reg,
            remove,
            forget_key,
            hex,
            wire,
        } => {
            let registration = registration(&host, reg).await?;
            let host_name = registration.host_name()?;
            let key = store.load(&host_name)?;
            let kind = if remove {
                UpdateKind::Remove { forget_key }
            } else {
                UpdateKind::Register
            };
            let (msg, bytes) = srp_client::signed_update(&registration, &key, kind, unix_now())?;

            println!(
                ";; SRP {} for {}",
                if remove { "removal" } else { "registration" },
                present_name(&host_name)
            );
            print_update(&msg, bytes.len());
            if hex {
                println!();
                print_hex(&bytes);
            }
            if let Some(path) = wire {
                std::fs::write(&path, &bytes)?;
                eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
            }
        }
    }
    Ok(())
}

/// Prints session progress. One-shot runs look like before phase 2; the
/// daemon also prints refreshes and retries.
struct EventPrinter {
    verbose: bool,
    daemon: bool,
    updates: u32,
}

impl EventPrinter {
    fn print(&mut self, event: Event<'_>) {
        match event {
            Event::Registered {
                registration,
                accepted,
                refresh_in,
            } => {
                self.updates += 1;
                let action = if self.updates == 1 {
                    "registered"
                } else {
                    "refreshed"
                };
                let name = registration
                    .host_name()
                    .map(|n| present_name(&n))
                    .unwrap_or_else(|_| registration.host.name.clone());
                println!("{action} {name} via {}", accepted.server);
                print_grant(accepted);
                if self.daemon {
                    println!("next refresh in {}", present_duration(refresh_in));
                }
                if self.verbose {
                    print_response(accepted);
                }
            }
            Event::Renamed { from, to } => {
                println!(
                    "conflict: renamed {} to {}",
                    present_name(&from),
                    present_name(&to)
                );
            }
            Event::Retrying { error, retry_in } => {
                eprintln!(
                    "srp: update failed: {error}; retrying in {}",
                    present_duration(retry_in)
                );
            }
        }
    }
}

/// Completes on SIGINT (Ctrl-C) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                eprintln!("srp: cannot watch SIGTERM: {e}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `5400` s → `1h30m0s`.
fn present_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    match (h, m) {
        (0, 0) if d < Duration::from_secs(1) => format!("{}ms", d.as_millis()),
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m{s}s"),
        _ => format!("{h}h{m}m{s}s"),
    }
}

async fn registration(host: &HostArgs, args: RegistrationArgs) -> CliResult<Registration> {
    let mut reg = Registration::new(Host {
        name: host.host.clone(),
        addresses: args.addresses,
    });
    reg.zone = host.zone.zone().await?;
    reg.lease = Duration::from_secs(args.lease);
    reg.key_lease = Duration::from_secs(args.key_lease);
    reg.ttl = Duration::from_secs(args.ttl);

    if let (Some(service_type), Some(instance), Some(port)) =
        (args.service, args.instance, args.port)
    {
        let mut svc = ServiceInstance::new(instance, service_type, port);
        svc.subtypes = args.subtypes;
        svc.txt = args.txt.into_iter().map(String::into_bytes).collect();
        svc.priority = args.priority;
        svc.weight = args.weight;
        reg.services.push(svc);
    }
    Ok(reg)
}

/// Parses `--server`. Literal addresses are used as is, names are resolved
/// and the first address is taken. Also returns the host name, if one was
/// given.
async fn resolve_server(
    server: &str,
    default_port: u16,
) -> CliResult<(SocketAddr, Option<String>)> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok((addr, None));
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok((SocketAddr::new(ip, default_port), None));
    }
    let (host, port) = match server.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>()?),
        None => (server, default_port),
    };
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| format!("{host} has no addresses"))?;
    Ok((addr, Some(host.trim_end_matches('.').to_owned())))
}

fn report(
    action: &str,
    reg: &Registration,
    accepted: &Accepted,
    verbose: bool,
) -> srp_client::Result<()> {
    println!(
        "{action} {} via {}",
        present_name(&reg.host_name()?),
        accepted.server
    );
    print_grant(accepted);
    if verbose {
        print_response(accepted);
    }
    Ok(())
}

fn print_grant(accepted: &Accepted) {
    let lease = accepted.lease();
    match accepted.granted {
        Some(_) => println!(
            "granted: LEASE={}s KEY-LEASE={}s",
            lease.lease,
            lease.key_lease()
        ),
        None => println!(
            "granted: no Update Lease in response, assuming LEASE={}s KEY-LEASE={}s",
            lease.lease,
            lease.key_lease()
        ),
    }
}

fn print_response(accepted: &Accepted) {
    println!("\n;; RESPONSE: {}", accepted.response.response_code());
    let size = accepted.response.to_vec().map(|v| v.len()).unwrap_or(0);
    print_update(&accepted.response, size);
    println!();
}

fn print_update(msg: &Message, size: usize) {
    println!(
        ";; id: {:#06x}  opcode: {}  size: {size} bytes",
        msg.id(),
        msg.op_code()
    );
    println!("\n;; ZONE SECTION:");
    for zone in msg.queries() {
        println!(
            "{}\t{}\t{}",
            present_name(zone.name()),
            zone.query_class(),
            zone.query_type()
        );
    }
    println!("\n;; PREREQUISITE SECTION: {} records", msg.answers().len());
    for record in msg.answers() {
        println!("{}", present_record(record));
    }
    println!("\n;; UPDATE SECTION:");
    for record in msg.name_servers() {
        println!("{}", present_record(record));
    }
    println!("\n;; ADDITIONAL SECTION:");
    for record in msg.additionals() {
        println!("{}", present_record(record));
    }
    if let Some(edns) = msg.extensions() {
        let lease = match Lease::from_message(msg) {
            Some(Ok(l)) => format!("LEASE={}s KEY-LEASE={}s", l.lease, l.key_lease()),
            Some(Err(e)) => format!("UPDATE-LEASE <{e}>"),
            None => "no UPDATE-LEASE".to_string(),
        };
        println!(
            ";; OPT: udp={} do={} {lease}",
            edns.max_payload(),
            u8::from(edns.flags().dnssec_ok)
        );
    }
    for record in msg.sig0() {
        println!("{}", present_record(record));
    }
}

fn present_record(record: &Record) -> String {
    let rdata = match record.data() {
        RData::Update0(_) => String::new(),
        RData::PTR(ptr) => present_name(&ptr.0),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority(),
            srv.weight(),
            srv.port(),
            present_name(srv.target())
        ),
        other => other.to_string(),
    };
    format!(
        "{}\t{}\t{}\t{}\t{}",
        present_name(record.name()),
        record.ttl(),
        record.dns_class(),
        record.record_type(),
        rdata
    )
    .trim_end()
    .to_string()
}

/// Presentation format per RFC 1035 section 5.1, with decimal `\DDD` escapes.
/// (hickory 0.25 escapes in octal.)
fn present_name(name: &Name) -> String {
    if name.is_root() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in name.iter() {
        for &b in label {
            match b {
                b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                    out.push('\\');
                    out.push(b as char);
                }
                0x21..=0x7e => out.push(b as char),
                _ => out.push_str(&format!("\\{b:03}")),
            }
        }
        out.push('.');
    }
    out
}

fn print_hex(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();
        println!("{:04x}  {:<47}  {ascii}", i * 16, hex.join(" "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn present_name_uses_decimal_escapes() {
        let name = Name::from_labels([b"My Printer".as_slice(), b"a.b", b"_ipp"]).unwrap();
        assert_eq!(present_name(&name), "My\\032Printer.a\\.b._ipp.");
        assert_eq!(present_name(&Name::root()), ".");
    }
}
