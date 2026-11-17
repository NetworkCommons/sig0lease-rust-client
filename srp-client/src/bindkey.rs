//! BIND key files: `K<name>+013+<tag>.key` and `.private`, as written by
//! `dnssec-keygen -T KEY` and used by `nsupdate -k` and sig0namectl.
//!
//! Only ECDSAP256SHA256 (algorithm 13) keys can be used, since that is the
//! only algorithm RFC 9665 allows. sig0namectl creates ED25519 keys by
//! default; those are rejected with a clear error.
//!
//! On export the KEY record gets the SRP flags 0x0201 ([`SRP_KEY_FLAGS`]),
//! so the key tag in the file name is the one SIG(0) uses. On import the
//! flags are ignored: SRP always publishes the key with its own flags.

use std::fs;
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::Name;

use crate::error::{Result, SrpError};
use crate::key::{SRP_ALGORITHM, SRP_KEY_FLAGS, SrpKey, write_private};

/// DNSSEC algorithm number of ECDSAP256SHA256.
const ALGORITHM_NUMBER: u8 = 13;

/// The two files of a BIND key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindKeyFiles {
    /// `K<name>+013+<tag>`, without extension.
    pub basename: String,
    /// Contents of `<basename>.key`: the public KEY record.
    pub key: String,
    /// Contents of `<basename>.private`.
    pub private: String,
}

impl BindKeyFiles {
    /// Writes `<dir>/<basename>.key` (mode 0644) and `.private` (mode 0600).
    /// Returns both paths. Refuses to overwrite existing files.
    pub fn write(&self, dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let key_path = dir.join(format!("{}.key", self.basename));
        let private_path = dir.join(format!("{}.private", self.basename));
        for path in [&key_path, &private_path] {
            if path.exists() {
                return Err(SrpError::KeyExists(path.clone()));
            }
        }
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| SrpError::Io { path, source }
        };
        fs::create_dir_all(dir).map_err(io(dir))?;
        fs::write(&key_path, &self.key).map_err(io(&key_path))?;
        write_private(&private_path, self.private.as_bytes()).map_err(io(&private_path))?;
        Ok((key_path, private_path))
    }
}

/// Formats `key` for `name` as BIND key files.
pub fn export(name: &Name, key: &SrpKey) -> Result<BindKeyFiles> {
    let mut name = name.clone();
    name.set_fqdn(true);
    let owner = name.to_ascii();
    let tag = key.signer(name.clone())?.calculate_key_tag()?;
    let public = BASE64.encode(key.public_key().public_bytes());
    let private = BASE64.encode(&key.private_scalar()?);
    Ok(BindKeyFiles {
        basename: format!("K{owner}+{ALGORITHM_NUMBER:03}+{tag:05}"),
        key: format!(
            "; This is a SIG(0) key for SRP, keyid {tag}, for {owner}\n\
             ; Written by srp {}\n\
             {owner} IN KEY {SRP_KEY_FLAGS} 3 {ALGORITHM_NUMBER} {public}\n",
            env!("CARGO_PKG_VERSION"),
        ),
        private: format!(
            "Private-key-format: v1.3\n\
             Algorithm: {ALGORITHM_NUMBER} ({})\n\
             PrivateKey: {private}\n",
            SRP_ALGORITHM.as_str(),
        ),
    })
}

/// Reads a BIND key pair. `path` may name either file, or the basename
/// without extension; the other file is found next to it.
pub fn read(path: &Path) -> Result<(Name, SrpKey)> {
    let base = match path.extension().and_then(|e| e.to_str()) {
        Some("key" | "private") => path.with_extension(""),
        _ => path.to_path_buf(),
    };
    // `with_extension` would cut at the last dot of the owner name, which is
    // part of the basename (`Kname.+013+12345`), so append instead.
    let with = |ext: &str| {
        let mut p = base.clone().into_os_string();
        p.push(ext);
        PathBuf::from(p)
    };
    let (key_path, private_path) = (with(".key"), with(".private"));
    let read = |path: &PathBuf| {
        fs::read_to_string(path).map_err(|source| SrpError::Io {
            path: path.clone(),
            source,
        })
    };
    let (key_text, private_text) = (read(&key_path)?, read(&private_path)?);
    let (name, public) = parse_key_file(&key_text).map_err(|reason| SrpError::KeyFormat {
        path: key_path,
        reason,
    })?;
    let private = parse_private_file(&private_text).map_err(|reason| SrpError::KeyFormat {
        path: private_path.clone(),
        reason,
    })?;
    let key = SrpKey::from_raw(&private, &public).map_err(|e| SrpError::KeyFormat {
        path: private_path,
        reason: format!("does not match the .key file: {e}"),
    })?;
    Ok((name, key))
}

/// Parses the KEY (or DNSKEY) record of a `.key` file: owner name and the
/// 64-byte public key.
pub fn parse_key_file(text: &str) -> std::result::Result<(Name, Vec<u8>), String> {
    // Drop comments and the parentheses of a multi-line record.
    let content: String = text
        .lines()
        .map(|line| line.split(';').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
        .replace(['(', ')'], " ");
    let mut tokens = content.split_whitespace();

    let owner = tokens.next().ok_or("no record found")?;
    if !owner.ends_with('.') {
        return Err(format!("owner name {owner:?} is not fully qualified"));
    }
    let name = Name::from_ascii(owner).map_err(|e| format!("owner name {owner:?}: {e}"))?;

    // Optional TTL and class, in either order, then the type.
    let rtype = loop {
        let token = tokens.next().ok_or("record type missing")?;
        let upper = token.to_ascii_uppercase();
        if token.bytes().all(|b| b.is_ascii_digit()) || matches!(upper.as_str(), "IN" | "CH" | "HS")
        {
            continue;
        }
        break upper;
    };
    if rtype != "KEY" && rtype != "DNSKEY" {
        return Err(format!("expected a KEY record, found {rtype}"));
    }

    let mut field = |what: &str| -> std::result::Result<u16, String> {
        let token = tokens.next().ok_or(format!("{what} missing"))?;
        token
            .parse::<u16>()
            .map_err(|_| format!("bad {what} {token:?}"))
    };
    let _flags = field("flags")?;
    let protocol = field("protocol")?;
    let algorithm = field("algorithm")?;
    if protocol != 3 {
        return Err(format!("protocol {protocol}, expected 3"));
    }
    check_algorithm(algorithm)?;

    let public: String = tokens.collect();
    let public = BASE64
        .decode(public.as_bytes())
        .map_err(|e| format!("public key: {e}"))?;
    if public.len() != 64 {
        return Err(format!(
            "public key is {} bytes, expected 64 for P-256",
            public.len()
        ));
    }
    Ok((name, public))
}

/// Parses a `.private` file (`Private-key-format: v1.x`) into the 32-byte
/// private scalar.
pub fn parse_private_file(text: &str) -> std::result::Result<Vec<u8>, String> {
    let mut format = None;
    let mut algorithm = None;
    let mut private = None;
    for line in text.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field.trim() {
            "Private-key-format" => format = Some(value),
            "Algorithm" => algorithm = value.split_whitespace().next(),
            "PrivateKey" => private = Some(value),
            _ => {}
        }
    }
    match format {
        Some(v) if v.starts_with("v1.") => {}
        Some(v) => return Err(format!("unsupported Private-key-format {v}")),
        None => return Err("not a BIND private key file (no Private-key-format)".into()),
    }
    let algorithm = algorithm.ok_or("Algorithm missing")?;
    check_algorithm(
        algorithm
            .parse()
            .map_err(|_| format!("bad Algorithm {algorithm:?}"))?,
    )?;
    let private = private.ok_or("PrivateKey missing")?;
    let private = BASE64
        .decode(private.as_bytes())
        .map_err(|e| format!("PrivateKey: {e}"))?;
    if private.len() != 32 {
        return Err(format!(
            "PrivateKey is {} bytes, expected 32 for P-256",
            private.len()
        ));
    }
    Ok(private)
}

fn check_algorithm(algorithm: u16) -> std::result::Result<(), String> {
    match algorithm {
        13 => Ok(()),
        15 => Err("algorithm 15 (ED25519) cannot be used: SRP requires ECDSAP256SHA256 \
             (13). Create one with `srp keygen` or `dnssec-keygen -a ECDSAP256SHA256 -T KEY -n HOST`"
            .into()),
        n => Err(format!(
            "algorithm {n} cannot be used: SRP requires ECDSAP256SHA256 (13)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key pair in the layout BIND 9.20 `dnssec-keygen -a ECDSAP256SHA256
    /// -T KEY -n HOST` writes (flags 512, timestamps), with the record split over
    /// two lines in parentheses, holding the test-only key of `message.rs`.
    const BIND_KEY: &str = "; This is a key-signing key, keyid 0, for printer.example.\n\
        ; Created: 20261103090000 (Tue Nov  3 10:00:00 2026)\n\
        printer.example. IN KEY 512 3 13 ( E6DFN1OkK7VMR0ubxgYsXSGgzKHLnWWUMpr5de5FGh1f\n\
        PxAXShx3niAkc0q6dVhaS55QKHFm2VUOL7phcNvYMA== ) ; comment\n";
    const BIND_PRIVATE: &str = "Private-key-format: v1.3\n\
        Algorithm: 13 (ECDSAP256SHA256)\n\
        PrivateKey: tcaAZPEjZMeaRnQhLALfF/QzKF/fQCoyt38h1Bae7yo=\n\
        Created: 20261103090000\n\
        Publish: 20261103090000\n\
        Activate: 20261103090000\n";

    /// Public half of the same test key, in the golden tests of `message.rs`.
    const PUBLIC_HEX: &str = "13a0c53753a42bb54c474b9bc6062c5d21a0cca1cb9d6594329af975ee451a1d\
        5f3f10174a1c779e2024734aba75585a4b9e50287166d9550e2fba6170dbd830";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn parses_bind_files() {
        let (name, public) = parse_key_file(BIND_KEY).unwrap();
        assert_eq!(name.to_ascii(), "printer.example.");
        assert_eq!(hex(&public), PUBLIC_HEX);
        let private = parse_private_file(BIND_PRIVATE).unwrap();
        let key = SrpKey::from_raw(&private, &public).unwrap();
        assert_eq!(hex(key.public_key().public_bytes()), PUBLIC_HEX);
    }

    #[test]
    fn export_import_roundtrip() {
        let key = SrpKey::generate().unwrap();
        let name = Name::from_ascii("printer-42.dev.zenr.io.").unwrap();
        let files = export(&name, &key).unwrap();
        assert!(files.basename.starts_with("Kprinter-42.dev.zenr.io.+013+"));
        assert!(
            files
                .key
                .contains("printer-42.dev.zenr.io. IN KEY 513 3 13 ")
        );

        let (owner, public) = parse_key_file(&files.key).unwrap();
        assert_eq!(owner, name);
        let private = parse_private_file(&files.private).unwrap();
        let again = SrpKey::from_raw(&private, &public).unwrap();
        assert_eq!(again.pkcs8(), key.pkcs8());

        // Through the file system, by either file name.
        let dir = std::env::temp_dir().join(format!("srp-bindkey-test-{}", std::process::id()));
        let (key_path, private_path) = files.write(&dir).unwrap();
        assert!(matches!(files.write(&dir), Err(SrpError::KeyExists(_))));
        for path in [&key_path, &private_path] {
            let (owner, loaded) = read(path).unwrap();
            assert_eq!(owner, name);
            assert_eq!(loaded.pkcs8(), key.pkcs8());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn key_tag_in_name_matches_sig0() {
        let key = SrpKey::generate().unwrap();
        let name = Name::from_ascii("h.example.").unwrap();
        let tag = key
            .signer(name.clone())
            .unwrap()
            .calculate_key_tag()
            .unwrap();
        let files = export(&name, &key).unwrap();
        assert!(files.basename.ends_with(&format!("+{tag:05}")));
        assert!(files.key.contains(&format!("keyid {tag},")));
    }

    #[test]
    fn rejects_other_algorithms_and_garbage() {
        let ed25519 = "example. 3600 IN KEY 512 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";
        assert!(parse_key_file(ed25519).unwrap_err().contains("ED25519"));
        assert!(parse_key_file("example. IN A 192.0.2.1").is_err());
        assert!(parse_key_file("example IN KEY 512 3 13 AAAA").is_err());
        assert!(parse_private_file("PrivateKey: AAAA").is_err());
        let rsa = BIND_PRIVATE.replace("13 (ECDSAP256SHA256)", "8 (RSASHA256)");
        assert!(parse_private_file(&rsa).is_err());
    }
}
