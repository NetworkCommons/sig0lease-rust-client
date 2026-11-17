//! Lifecycle test against a live SRP registrar. Ignored by default; run with
//!
//! ```text
//! cargo test -p srp-client --test live -- --ignored
//! ```
//!
//! `SRP_LIVE_SERVER` (default `sig0lease.dev.zenr.io:8053`) and
//! `SRP_LIVE_ZONE` (default `dev.zenr.io`) select the registrar.

use std::net::SocketAddr;
use std::time::Duration;

use srp_client::model::parse_zone;
use srp_client::{
    ConflictPolicy, Event, Host, Registration, ServiceInstance, Session, SessionConfig, SrpClient,
    SrpError, SrpKey,
};

/// The test registrar sometimes answers SERVFAIL when the two tests send
/// updates at the same time (seen 2 of ~10 parallel runs, never serially).
/// Probably its upstream: BIND 9.20 refuses SIG(0) updates beyond its
/// `sig0checks-quota`. So the live tests run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn server() -> SocketAddr {
    let server =
        std::env::var("SRP_LIVE_SERVER").unwrap_or_else(|_| "sig0lease.dev.zenr.io:8053".into());
    tokio::net::lookup_host(server.as_str())
        .await
        .expect("resolve SRP_LIVE_SERVER")
        .next()
        .expect("SRP_LIVE_SERVER has an address")
}

fn registration(host: &str) -> Registration {
    let zone = std::env::var("SRP_LIVE_ZONE").unwrap_or_else(|_| "dev.zenr.io".into());
    let mut reg = Registration::new(Host {
        name: host.into(),
        addresses: vec![
            "192.0.2.42".parse().unwrap(),
            "2001:db8::42".parse().unwrap(),
        ],
    });
    reg.zone = parse_zone(&zone).unwrap();
    // Short leases, so a failed run cleans up after itself.
    reg.lease = Duration::from_secs(60);
    reg.key_lease = Duration::from_secs(120);
    let mut svc = ServiceInstance::new(format!("{host} test"), "_http._tcp", 8080);
    svc.txt.push(b"path=/".to_vec());
    reg.services.push(svc);
    reg
}

#[tokio::test]
#[ignore = "talks to a live SRP registrar"]
async fn register_conflict_remove() {
    let _serial = SERIAL.lock().await;
    let client = SrpClient::new(server().await);
    let host = format!("srp-rs-it-{:08x}", rand::random::<u32>());
    let reg = registration(&host);
    let key = SrpKey::generate().unwrap();

    let accepted = client.register(&reg, &key).await.unwrap();
    let lease = accepted.lease();
    assert!(lease.lease > 0 && lease.lease <= 60, "granted {lease:?}");

    // Refreshing with the same key is accepted.
    client.register(&reg, &key).await.unwrap();

    // The name belongs to `key` now.
    let intruder = SrpKey::generate().unwrap();
    let err = client.register(&reg, &intruder).await.unwrap_err();
    assert!(matches!(err, SrpError::Conflict(_)), "got {err}");

    // Releasing the name lets the other key take it.
    let removed = client.remove(&reg, &key, true).await.unwrap();
    assert_eq!(removed.lease().lease, 0);
    client.register(&reg, &intruder).await.unwrap();
    client.remove(&reg, &intruder, true).await.unwrap();
}

#[tokio::test]
#[ignore = "talks to a live SRP registrar"]
async fn session_renames_and_drops_instances() {
    let _serial = SERIAL.lock().await;
    let client = SrpClient::new(server().await);
    let host = format!("srp-rs-it-{:08x}", rand::random::<u32>());
    let reg = registration(&host);

    // The first owner takes the host and the instance name.
    let owner = SrpKey::generate().unwrap();
    client.register(&reg, &owner).await.unwrap();

    // A second key with the same names renames both.
    let config = SessionConfig {
        conflict: ConflictPolicy::Rename { max_renames: 3 },
        ..SessionConfig::default()
    };
    let mut session = Session::new(
        client.clone(),
        SrpKey::generate().unwrap(),
        reg.clone(),
        config,
    );
    let mut renames = 0;
    session
        .register(&mut |e: Event<'_>| {
            if let Event::Renamed { from, to } = e {
                eprintln!("renamed {from} -> {to}");
                renames += 1;
            }
        })
        .await
        .unwrap();
    assert_eq!(renames, 2);
    let renamed = session.registration();
    assert_eq!(renamed.host.name, format!("{host}-2"));
    assert_eq!(renamed.services[0].instance, format!("{host} test (2)"));

    // Dropping the service deletes the renamed instance in the next update.
    let mut fewer = reg.clone();
    fewer.services.clear();
    session.update(fewer, &mut |_| {}).await.unwrap();

    session.remove(true).await.unwrap();
    client.remove(&reg, &owner, true).await.unwrap();
}
