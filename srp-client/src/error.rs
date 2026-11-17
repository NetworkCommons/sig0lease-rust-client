use std::net::SocketAddr;
use std::path::PathBuf;

use hickory_proto::ProtoError;
use hickory_proto::dnssec::DnsSecError;
use hickory_proto::op::ResponseCode;

/// Errors produced by the SRP client.
#[derive(Debug, thiserror::Error)]
pub enum SrpError {
    #[error("DNS protocol error: {0}")]
    Proto(#[from] ProtoError),

    #[error("DNSSEC/crypto error: {0}")]
    DnsSec(#[from] DnsSecError),

    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("no key for host found at {0} (run `srp keygen` first)")]
    KeyMissing(PathBuf),

    #[error("key already exists at {0}")]
    KeyExists(PathBuf),

    #[error("bad key file {path}: {reason}")]
    KeyFormat { path: PathBuf, reason: String },

    #[error("discovery failed: {0}")]
    Discovery(String),

    #[error("invalid name {name:?}: {reason}")]
    InvalidName { name: String, reason: String },

    #[error("malformed Update Lease option: {0}")]
    MalformedLease(String),

    #[error("network error talking to {server}: {source}")]
    Network {
        server: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("no response from {server} after {attempts} attempts")]
    Timeout { server: SocketAddr, attempts: u32 },

    #[error("malformed response from {server}: {reason}")]
    MalformedResponse { server: SocketAddr, reason: String },

    #[error("response from {server} was truncated")]
    Truncated { server: SocketAddr },

    /// YXDOMAIN: the host name or one of the instance names is owned by a
    /// different key. The response does not say which; the value is the host.
    #[error(
        "name conflict: {0} or one of its service instances is registered with a different key (YXDOMAIN)"
    )]
    Conflict(String),

    #[error("registrar rejected the update: {rcode}{}", hint.map(|h| format!(" ({h})")).unwrap_or_default())]
    Rejected {
        rcode: ResponseCode,
        hint: Option<&'static str>,
    },
}

impl SrpError {
    /// Whether retrying the same update later may succeed: timeouts, network
    /// errors and SERVFAIL. Conflicts and other rejections need a change first.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network { .. }
            | Self::Timeout { .. }
            | Self::Truncated { .. }
            | Self::MalformedResponse { .. } => true,
            Self::Rejected { rcode, .. } => *rcode == ResponseCode::ServFail,
            _ => false,
        }
    }

    pub(crate) fn invalid_name(name: impl Into<String>, reason: impl ToString) -> Self {
        Self::InvalidName {
            name: name.into(),
            reason: reason.to_string(),
        }
    }
}

pub type Result<T, E = SrpError> = std::result::Result<T, E>;
