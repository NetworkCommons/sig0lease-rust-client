//! EDNS(0) Update Lease option (RFC 9664).
//!
//! hickory-proto knows the code (`EdnsCode::UL`) but has no typed payload, so
//! the option is carried as `EdnsOption::Unknown(2, ..)`.

use std::time::Duration;

use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

use crate::error::{Result, SrpError};

/// EDNS(0) option code assigned to Update Lease.
pub const UPDATE_LEASE_OPTION_CODE: u16 = 2;

/// Lease values carried in an SRP update or returned by the registrar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// Lifetime of the registered records, in seconds.
    pub lease: u32,
    /// Lifetime of the KEY (name reservation), in seconds. `None` encodes the
    /// short 4-byte variant, where KEY-LEASE equals LEASE.
    pub key_lease: Option<u32>,
}

impl Lease {
    pub fn new(lease: Duration, key_lease: Duration) -> Self {
        Self {
            lease: saturating_secs(lease),
            key_lease: Some(saturating_secs(key_lease)),
        }
    }

    /// Lease for removing the registration. With `forget_key` the KEY
    /// reservation is released as well, otherwise it is kept for `key_lease`.
    pub fn remove(key_lease: Duration, forget_key: bool) -> Self {
        Self {
            lease: 0,
            key_lease: Some(if forget_key {
                0
            } else {
                saturating_secs(key_lease)
            }),
        }
    }

    /// Effective KEY-LEASE: the short variant implies KEY-LEASE == LEASE.
    pub fn key_lease(&self) -> u32 {
        self.key_lease.unwrap_or(self.lease)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.lease.to_be_bytes().to_vec();
        if let Some(key_lease) = self.key_lease {
            bytes.extend_from_slice(&key_lease.to_be_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let u32_at = |i: usize| u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
        match bytes.len() {
            4 => Ok(Self {
                lease: u32_at(0),
                key_lease: None,
            }),
            8 => Ok(Self {
                lease: u32_at(0),
                key_lease: Some(u32_at(4)),
            }),
            n => Err(SrpError::MalformedLease(format!(
                "expected 4 or 8 bytes, got {n}"
            ))),
        }
    }

    pub fn to_edns_option(&self) -> EdnsOption {
        EdnsOption::Unknown(UPDATE_LEASE_OPTION_CODE, self.to_bytes())
    }

    /// Extracts the Update Lease from an EDNS option, if it is one.
    pub fn from_edns_option(option: &EdnsOption) -> Option<Result<Self>> {
        match option {
            EdnsOption::Unknown(UPDATE_LEASE_OPTION_CODE, data) => Some(Self::from_bytes(data)),
            _ => None,
        }
    }

    /// Finds the Update Lease option in a message's OPT record.
    pub fn from_message(message: &hickory_proto::op::Message) -> Option<Result<Self>> {
        let edns = message.extensions().as_ref()?;
        let option = edns
            .options()
            .get(EdnsCode::from(UPDATE_LEASE_OPTION_CODE))?;
        Self::from_edns_option(option)
    }
}

fn saturating_secs(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_variant_roundtrip() {
        let lease = Lease::new(Duration::from_secs(7200), Duration::from_secs(1_209_600));
        let bytes = lease.to_bytes();
        assert_eq!(bytes, [0, 0, 0x1c, 0x20, 0, 0x12, 0x75, 0]);
        assert_eq!(Lease::from_bytes(&bytes).unwrap(), lease);
    }

    #[test]
    fn short_variant() {
        let lease = Lease::from_bytes(&[0, 0, 0x0e, 0x10]).unwrap();
        assert_eq!(lease.lease, 3600);
        assert_eq!(lease.key_lease(), 3600);
        assert_eq!(lease.to_bytes().len(), 4);
    }

    #[test]
    fn bad_length() {
        assert!(Lease::from_bytes(&[0, 0, 1]).is_err());
    }

    #[test]
    fn remove() {
        let keep = Lease::remove(Duration::from_secs(100), false);
        assert_eq!((keep.lease, keep.key_lease()), (0, 100));
        let forget = Lease::remove(Duration::from_secs(100), true);
        assert_eq!((forget.lease, forget.key_lease()), (0, 0));
    }
}
