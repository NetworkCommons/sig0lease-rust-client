//! What gets registered: one host with its addresses and 0..n service instances.

use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::rr::Name;

use crate::error::{Result, SrpError};

/// Registration domain used when none is discovered or configured.
pub const DEFAULT_ZONE: &str = "default.service.arpa.";
pub const DEFAULT_LEASE: Duration = Duration::from_secs(2 * 3600);
pub const DEFAULT_KEY_LEASE: Duration = Duration::from_secs(14 * 24 * 3600);
pub const DEFAULT_TTL: Duration = Duration::from_secs(2 * 3600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// Single host label, e.g. `printer-42`.
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstance {
    /// Instance label, free-form UTF-8 (e.g. `My Printer`).
    pub instance: String,
    /// Service type, e.g. `_ipp._tcp`.
    pub service_type: String,
    /// Subtype labels, e.g. `_universal`.
    pub subtypes: Vec<String>,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    /// TXT strings, e.g. `rp=ipp/print`. Empty means a single empty string,
    /// as required by RFC 6763 section 6.1.
    pub txt: Vec<Vec<u8>>,
}

impl ServiceInstance {
    pub fn new(instance: impl Into<String>, service_type: impl Into<String>, port: u16) -> Self {
        Self {
            instance: instance.into(),
            service_type: service_type.into(),
            subtypes: Vec::new(),
            port,
            priority: 0,
            weight: 0,
            txt: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub zone: Name,
    pub host: Host,
    pub services: Vec<ServiceInstance>,
    pub lease: Duration,
    pub key_lease: Duration,
    /// TTL of the registered records; capped at the lease.
    pub ttl: Duration,
}

impl Registration {
    pub fn new(host: Host) -> Self {
        Self {
            zone: Name::from_ascii(DEFAULT_ZONE).expect("valid default zone"),
            host,
            services: Vec::new(),
            lease: DEFAULT_LEASE,
            key_lease: DEFAULT_KEY_LEASE,
            ttl: DEFAULT_TTL,
        }
    }

    /// Fully qualified host name, `<host>.<zone>`.
    pub fn host_name(&self) -> Result<Name> {
        host_name(&self.host.name, &self.zone)
    }
}

/// Builds `<host>.<zone>`. The host must be a single label that is also safe
/// as a key file name.
pub fn host_name(host: &str, zone: &Name) -> Result<Name> {
    let valid = !host.is_empty()
        && host.len() <= 63
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(SrpError::invalid_name(
            host,
            "host must be a single label of letters, digits, '-' or '_'",
        ));
    }
    Ok(Name::from_labels([host.as_bytes()])?.append_domain(zone)?)
}

/// Parses a zone name, making it fully qualified.
pub fn parse_zone(zone: &str) -> Result<Name> {
    let mut name = Name::from_ascii(zone).map_err(|e| SrpError::invalid_name(zone, e))?;
    name.set_fqdn(true);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_name_is_qualified() {
        let zone = parse_zone("default.service.arpa").unwrap();
        let name = host_name("printer-42", &zone).unwrap();
        assert_eq!(name.to_ascii(), "printer-42.default.service.arpa.");
    }

    #[test]
    fn host_name_rejects_dots_and_slashes() {
        let zone = parse_zone(DEFAULT_ZONE).unwrap();
        assert!(host_name("a.b", &zone).is_err());
        assert!(host_name("../etc", &zone).is_err());
        assert!(host_name("", &zone).is_err());
    }
}
