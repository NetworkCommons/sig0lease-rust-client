//! DNS-over-TLS (RFC 7858) to an SRP registrar.
//!
//! RFC 9665 section 7 uses TLS for privacy only. A requester has no way to
//! learn a registrar's certificate in advance, and SIG(0) already
//! authenticates the update, so the default is RFC 7858's Opportunistic
//! Privacy profile (section 4.1): the connection is encrypted, but the
//! registrar's certificate is not checked. That protects against passive
//! eavesdroppers, not against an active attacker in the path. Handshake
//! signatures are still verified, so the session key belongs to the
//! certificate the server presented. sig0lease does the same.
//!
//! [`TlsConfig::with_client_config`] takes a rustls configuration with a real
//! certificate verifier for a strict profile.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Port assigned to DNS-over-TLS (RFC 7858 section 3.1).
pub const DOT_PORT: u16 = 853;

/// ALPN identifier for DNS-over-TLS (RFC 7858, IANA "dot").
pub const DOT_ALPN: &[u8] = b"dot";

/// How to set up the TLS session.
#[derive(Clone)]
pub struct TlsConfig {
    client: Arc<ClientConfig>,
    server_name: Option<ServerName<'static>>,
}

impl TlsConfig {
    /// Opportunistic privacy: any certificate is accepted. ALPN `dot` is
    /// offered.
    pub fn opportunistic() -> Self {
        static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
        let client = CONFIG
            .get_or_init(|| {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let mut config = ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default TLS versions")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                    .with_no_client_auth();
                config.alpn_protocols = vec![DOT_ALPN.to_vec()];
                Arc::new(config)
            })
            .clone();
        Self {
            client,
            server_name: None,
        }
    }

    /// Uses `client` as is, for example with a WebPKI verifier for a strict
    /// profile. Set its `alpn_protocols` to [`DOT_ALPN`] if the registrar
    /// expects it.
    pub fn with_client_config(client: Arc<ClientConfig>) -> Self {
        Self {
            client,
            server_name: None,
        }
    }

    /// The name sent in SNI and, with a verifying configuration, checked
    /// against the certificate. Without it, the server's IP address is used
    /// and no SNI is sent.
    pub fn with_server_name(mut self, name: ServerName<'static>) -> Self {
        self.server_name = Some(name);
        self
    }

    pub fn server_name(&self) -> Option<&ServerName<'static>> {
        self.server_name.as_ref()
    }

    /// Runs the TLS handshake on `tcp`, connected to `server`.
    pub(crate) async fn connect(
        &self,
        server: SocketAddr,
        tcp: TcpStream,
    ) -> std::io::Result<TlsStream<TcpStream>> {
        let name = self
            .server_name
            .clone()
            .unwrap_or_else(|| ServerName::IpAddress(server.ip().into()));
        TlsConnector::from(self.client.clone())
            .connect(name, tcp)
            .await
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::opportunistic()
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("server_name", &self.server_name)
            .field("alpn", &self.client.alpn_protocols)
            .finish_non_exhaustive()
    }
}

/// Accepts any certificate, but still checks that the handshake was signed
/// by the key in it.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
