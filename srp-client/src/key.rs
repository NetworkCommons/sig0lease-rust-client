//! SRP host keys: ECDSA P-256 (DNSSEC algorithm 13), stored as PKCS#8 DER.
//!
//! The key is the identity behind the first-come-first-served name claim, so
//! it must be persisted and reused across restarts.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::KEY;
#[allow(deprecated)]
use hickory_proto::dnssec::rdata::key::{KeyTrust, KeyUsage, Protocol, UpdateScope};
use hickory_proto::dnssec::{Algorithm, PublicKey, PublicKeyBuf, SigSigner, SigningKey};
use hickory_proto::rr::Name;
use rustls_pki_types::PrivatePkcs8KeyDer;

use crate::error::{Result, SrpError};

/// The only algorithm RFC 9665 requires: ECDSAP256SHA256.
pub const SRP_ALGORITHM: Algorithm = Algorithm::ECDSAP256SHA256;

/// KEY flags used by SRP clients: owner = non-zone entity (0x0200),
/// signatory = general update (0x0001). Matches OpenThread's SRP client.
pub const SRP_KEY_FLAGS: u16 = 0x0201;

/// An SRP host key pair.
pub struct SrpKey {
    pkcs8: Vec<u8>,
    public: PublicKeyBuf,
}

impl SrpKey {
    /// Generates a fresh P-256 key pair.
    pub fn generate() -> Result<Self> {
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(SRP_ALGORITHM)?;
        Self::from_pkcs8(pkcs8.secret_pkcs8_der().to_vec())
    }

    /// Loads a key pair from PKCS#8 DER bytes.
    pub fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self> {
        let signing = Self::parse(&pkcs8)?;
        let public = signing.to_public_key()?;
        Ok(Self { pkcs8, public })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Builds a key pair from the raw private scalar (32 bytes) and the public
    /// key (64 bytes, X || Y), as found in BIND key files. Fails if they do not
    /// belong together.
    pub fn from_raw(private: &[u8], public: &[u8]) -> Result<Self> {
        if private.len() != 32 || public.len() != 64 {
            return Err(SrpError::DnsSec(hickory_proto::dnssec::DnsSecError::from(
                format!(
                    "P-256 key needs a 32-byte private and 64-byte public key, got {} and {}",
                    private.len(),
                    public.len()
                ),
            )));
        }
        let mut pkcs8 = Vec::with_capacity(138);
        pkcs8.extend_from_slice(PKCS8_PREFIX);
        pkcs8.extend_from_slice(private);
        pkcs8.extend_from_slice(PKCS8_PUBLIC);
        pkcs8.extend_from_slice(public);
        // ring derives the public key from the scalar and rejects a mismatch
        // (`raw_rejects_mismatched_public_key`).
        Self::from_pkcs8(pkcs8)
    }

    /// The raw private scalar (32 bytes), as written to BIND key files.
    pub fn private_scalar(&self) -> Result<Vec<u8>> {
        ec_private_scalar(&self.pkcs8).ok_or_else(|| {
            SrpError::DnsSec(hickory_proto::dnssec::DnsSecError::from(
                "unexpected PKCS#8 layout".to_string(),
            ))
        })
    }

    /// Raw public key in DNSKEY/KEY wire form (64 bytes, X || Y).
    pub fn public_key(&self) -> &PublicKeyBuf {
        &self.public
    }

    /// KEY rdata advertised for the host (and optionally service instances).
    pub fn key_rdata(&self) -> KEY {
        #[allow(deprecated)] // UpdateScope is deprecated by RFC 3007, but SRP still sets it
        let scope = UpdateScope {
            general: true,
            ..UpdateScope::default()
        };
        KEY::new(
            KeyTrust::AuthOrPrivate,
            KeyUsage::Entity,
            scope,
            Protocol::DNSSEC,
            SRP_ALGORITHM,
            self.public.public_bytes().to_vec(),
        )
    }

    /// SIG(0) signer for updates on behalf of `host` (the signer name).
    pub fn signer(&self, host: Name) -> Result<SigSigner> {
        let signing = Self::parse(&self.pkcs8)?;
        Ok(SigSigner::sig0(self.key_rdata(), Box::new(signing), host))
    }

    fn parse(pkcs8: &[u8]) -> Result<EcdsaSigningKey> {
        Ok(EcdsaSigningKey::from_pkcs8(
            &PrivatePkcs8KeyDer::from(pkcs8),
            SRP_ALGORITHM,
        )?)
    }
}

/// PKCS#8 PrivateKeyInfo for an EC P-256 key (RFC 5208, RFC 5915), up to the
/// private scalar: SEQUENCE { INTEGER 0, SEQUENCE { id-ecPublicKey,
/// prime256v1 }, OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING (32) ...
/// This is the layout ring generates.
const PKCS8_PREFIX: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20,
];
/// After the scalar: [1] { BIT STRING { 0x00, 0x04 (uncompressed) ...
const PKCS8_PUBLIC: &[u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00, 0x04];

/// One DER element: (tag, contents, rest).
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, input) = input.split_first()?;
    let (&first, input) = input.split_first()?;
    let (len, input) = match first {
        0..=0x7f => (usize::from(first), input),
        0x81 => (usize::from(*input.first()?), &input[1..]),
        0x82 => (
            usize::from(u16::from_be_bytes([*input.first()?, *input.get(1)?])),
            input.get(2..)?,
        ),
        _ => return None,
    };
    let contents = input.get(..len)?;
    Some((tag, contents, &input[len..]))
}

/// The privateKey of the ECPrivateKey inside a PKCS#8 PrivateKeyInfo.
fn ec_private_scalar(pkcs8: &[u8]) -> Option<Vec<u8>> {
    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    const OCTET_STRING: u8 = 0x04;
    let (SEQUENCE, info, _) = der(pkcs8)? else {
        return None;
    };
    let (INTEGER, _version, info) = der(info)? else {
        return None;
    };
    let (SEQUENCE, _algorithm, info) = der(info)? else {
        return None;
    };
    let (OCTET_STRING, ec_key, _) = der(info)? else {
        return None;
    };
    let (SEQUENCE, ec_key, _) = der(ec_key)? else {
        return None;
    };
    let (INTEGER, _version, ec_key) = der(ec_key)? else {
        return None;
    };
    let (OCTET_STRING, scalar, _) = der(ec_key)? else {
        return None;
    };
    // RFC 5915 fixes the length, but pad a shortened encoding anyway.
    let mut out = vec![0u8; 32usize.checked_sub(scalar.len())?];
    out.extend_from_slice(scalar);
    Some(out)
}

impl std::fmt::Debug for SrpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpKey")
            .field("algorithm", &SRP_ALGORITHM)
            .field("public", &self.public.public_bytes())
            .finish_non_exhaustive()
    }
}

/// Directory holding one key file per host name.
#[derive(Debug, Clone)]
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Key file for a fully qualified host name, e.g.
    /// `printer-42.default.service.arpa.srp.pk8`.
    pub fn path_for(&self, host: &Name) -> PathBuf {
        let name = host.to_ascii();
        let name = name.trim_end_matches('.');
        self.dir.join(format!("{name}.srp.pk8"))
    }

    pub fn load(&self, host: &Name) -> Result<SrpKey> {
        let path = self.path_for(host);
        match fs::read(&path) {
            Ok(pkcs8) => SrpKey::from_pkcs8(pkcs8),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SrpError::KeyMissing(path)),
            Err(source) => Err(SrpError::Io { path, source }),
        }
    }

    /// Generates and stores a new key. Refuses to overwrite an existing key
    /// unless `force` is set, since replacing it gives up the name claim.
    pub fn generate(&self, host: &Name, force: bool) -> Result<(SrpKey, PathBuf)> {
        let path = self.path_for(host);
        if path.exists() && !force {
            return Err(SrpError::KeyExists(path));
        }
        let key = SrpKey::generate()?;
        let path = self.store(host, &key, force)?;
        Ok((key, path))
    }

    /// Stores `key` for `host`, e.g. one imported from BIND key files. Refuses
    /// to overwrite an existing key unless `force` is set.
    pub fn store(&self, host: &Name, key: &SrpKey, force: bool) -> Result<PathBuf> {
        let path = self.path_for(host);
        if path.exists() && !force {
            return Err(SrpError::KeyExists(path));
        }
        fs::create_dir_all(&self.dir).map_err(|source| SrpError::Io {
            path: self.dir.clone(),
            source,
        })?;
        write_private(&path, key.pkcs8()).map_err(|source| SrpError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }
}

/// Writes via a temporary file so a crash never leaves a truncated key behind.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("pk8.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rdata_matches_srp_profile() {
        let key = SrpKey::generate().unwrap();
        let rdata = key.key_rdata();
        assert_eq!(rdata.flags(), SRP_KEY_FLAGS);
        assert_eq!(rdata.algorithm(), Algorithm::ECDSAP256SHA256);
        assert_eq!(rdata.public_key().len(), 64);
    }

    #[test]
    fn raw_roundtrip() {
        let key = SrpKey::generate().unwrap();
        let scalar = key.private_scalar().unwrap();
        assert_eq!(scalar.len(), 32);
        let again = SrpKey::from_raw(&scalar, key.public_key().public_bytes()).unwrap();
        assert_eq!(again.pkcs8(), key.pkcs8());
    }

    #[test]
    fn raw_rejects_mismatched_public_key() {
        let a = SrpKey::generate().unwrap();
        let b = SrpKey::generate().unwrap();
        let err = SrpKey::from_raw(&a.private_scalar().unwrap(), b.public_key().public_bytes());
        assert!(err.is_err());
        assert!(SrpKey::from_raw(&[1; 31], a.public_key().public_bytes()).is_err());
    }

    #[test]
    fn keystore_roundtrip() {
        let dir = std::env::temp_dir().join(format!("srp-keystore-test-{}", std::process::id()));
        let store = KeyStore::new(&dir);
        let host = Name::from_ascii("printer-42.default.service.arpa.").unwrap();

        assert!(matches!(store.load(&host), Err(SrpError::KeyMissing(_))));
        let (key, path) = store.generate(&host, false).unwrap();
        assert!(path.ends_with("printer-42.default.service.arpa.srp.pk8"));
        assert!(matches!(
            store.generate(&host, false),
            Err(SrpError::KeyExists(_))
        ));
        let loaded = store.load(&host).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());

        fs::remove_dir_all(dir).unwrap();
    }
}
