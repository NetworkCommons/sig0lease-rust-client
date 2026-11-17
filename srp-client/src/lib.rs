//! DNS-SD Service Registration Protocol (RFC 9665) client, built on hickory-proto.
//!
//! Phase 0: data model, key management, Update Lease option and signed
//! update construction.
//! Phase 1: UDP/TCP transport and one-shot register/remove against an explicit
//! registrar.
//! Phase 2: [`Session`]: refresh on the granted lease, conflict renaming,
//! deletion of dropped instances.
//! Phase 3: DNS-over-TLS ([`Transport::Tls`], [`tls`]), registrar discovery
//! ([`discovery`]), BIND key files ([`bindkey`]).

pub mod bindkey;
pub mod client;
pub mod discovery;
pub mod error;
pub mod key;
pub mod lease;
pub mod message;
pub mod model;
pub mod session;
pub mod tls;
pub mod transport;

pub use client::{Accepted, Endpoint, SrpClient};
pub use discovery::{DiscoveryMode, DiscoveryOptions, Resolver};
pub use error::{Result, SrpError};
pub use key::{KeyStore, SrpKey};
pub use lease::Lease;
pub use message::{
    UpdateKind, build_update, build_update_removing, sign, signed_update, signed_update_removing,
};
pub use model::{Host, Registration, ServiceInstance};
pub use session::{ConflictPolicy, Event, Session, SessionConfig};
pub use tls::TlsConfig;
pub use transport::{RetryPolicy, Transport};
