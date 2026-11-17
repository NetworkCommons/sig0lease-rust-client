//! Builds SRP updates (RFC 9665 section 2.3) as hickory `Message`s.
//!
//! Instruction order follows OpenThread's SRP client: for each service the
//! Service Discovery and Service Description instructions, then the Host
//! Description instruction. The OPT record carries the Update Lease option,
//! and SIG(0) is appended last by [`sign`].

use std::net::IpAddr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, UpdateMessage};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::error::{Result, SrpError};
use crate::key::SrpKey;
use crate::lease::Lease;
use crate::model::{Registration, ServiceInstance};

/// UDP payload size advertised in the OPT record.
pub const EDNS_UDP_PAYLOAD: u16 = 1232;

/// How far SIG(0) inception is backdated. hickory signs with the validity
/// window `[time, time + 300 s]`, so a registrar whose clock is even a second
/// behind would see a signature from the future. Signing at `now - 150 s`
/// centres the window on `now`, tolerating 150 s of skew either way.
pub const SIG0_BACKDATE: u32 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateKind {
    /// Add or refresh the registration.
    Register,
    /// Remove the records (LEASE=0). With `forget_key`, KEY-LEASE=0 also
    /// releases the name reservation.
    Remove { forget_key: bool },
}

/// Builds an unsigned SRP update for `reg`. The message ID is random.
pub fn build_update(reg: &Registration, key: &SrpKey, kind: UpdateKind) -> Result<Message> {
    build_update_removing(reg, &[], key, kind)
}

/// Like [`build_update`], but also deletes the instances in `stale`: services
/// that an earlier update registered and `reg` no longer contains. SRP has no
/// garbage collection, so a dropped instance must be deleted explicitly. In a
/// [`UpdateKind::Remove`] the stale instances are removed along with the rest.
pub fn build_update_removing(
    reg: &Registration,
    stale: &[ServiceInstance],
    key: &SrpKey,
    kind: UpdateKind,
) -> Result<Message> {
    let removing = matches!(kind, UpdateKind::Remove { .. });
    let ttl = u32::try_from(reg.ttl.min(reg.lease).as_secs()).unwrap_or(u32::MAX);
    let host = reg.host_name()?;

    let mut msg = Message::new();
    msg.set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update);
    msg.add_zone(Query::query(reg.zone.clone(), RecordType::SOA));

    for svc in stale {
        add_service_removal(&mut msg, &ServiceNames::new(svc, &reg.zone)?);
    }

    for svc in &reg.services {
        let names = ServiceNames::new(svc, &reg.zone)?;
        if removing {
            add_service_removal(&mut msg, &names);
            continue;
        }

        // Service Discovery Instruction
        msg.add_update(Record::from_rdata(
            names.service.clone(),
            ttl,
            RData::PTR(PTR(names.instance.clone())),
        ));
        for subtype in &names.subtypes {
            msg.add_update(Record::from_rdata(
                subtype.clone(),
                ttl,
                RData::PTR(PTR(names.instance.clone())),
            ));
        }

        // Service Description Instruction
        msg.add_update(delete_all_rrsets(names.instance.clone()));
        msg.add_update(Record::from_rdata(
            names.instance.clone(),
            ttl,
            RData::SRV(SRV::new(svc.priority, svc.weight, svc.port, host.clone())),
        ));
        msg.add_update(Record::from_rdata(
            names.instance.clone(),
            ttl,
            RData::TXT(txt(&svc.txt)),
        ));
    }

    // Host Description Instruction. A removal carries no address adds: RFC 9665
    // section 3.3.1.3 signals host removal structurally, and sig0lease and
    // mDNSResponder only remove the addresses then. OpenThread removes them on
    // LEASE=0 either way.
    msg.add_update(delete_all_rrsets(host.clone()));
    let addresses = if removing {
        &[][..]
    } else {
        &reg.host.addresses[..]
    };
    for addr in addresses {
        let rdata = match addr {
            IpAddr::V4(v4) => RData::A(A(*v4)),
            IpAddr::V6(v6) => RData::AAAA(AAAA(*v6)),
        };
        msg.add_update(Record::from_rdata(host.clone(), ttl, rdata));
    }
    msg.add_update(Record::from_rdata(host, ttl, RData::from(key.key_rdata())));

    let lease = match kind {
        UpdateKind::Register => Lease::new(reg.lease, reg.key_lease.max(reg.lease)),
        UpdateKind::Remove { forget_key } => Lease::remove(reg.key_lease, forget_key),
    };
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_UDP_PAYLOAD).set_dnssec_ok(true);
    edns.options_mut().insert(lease.to_edns_option());
    msg.set_edns(edns);

    Ok(msg)
}

/// Appends SIG(0) by `signer_name` (the host name) and returns the wire bytes.
/// `now` is the current time; the signature is valid from `now - 150 s` to
/// `now + 150 s` (see [`SIG0_BACKDATE`]).
///
/// The returned bytes are exactly what was signed (plus the SIG record), so
/// they must be sent unchanged; retransmissions reuse them. Any earlier
/// signature is discarded, so a modified message can be signed again.
pub fn sign(msg: &mut Message, key: &SrpKey, signer_name: Name, now: u32) -> Result<Vec<u8>> {
    msg.take_signature();
    let signer = key.signer(signer_name)?;
    msg.finalize(&signer, now.wrapping_sub(SIG0_BACKDATE))?;
    Ok(msg.to_vec()?)
}

/// Builds and signs an update in one step.
pub fn signed_update(
    reg: &Registration,
    key: &SrpKey,
    kind: UpdateKind,
    now: u32,
) -> Result<(Message, Vec<u8>)> {
    signed_update_removing(reg, &[], key, kind, now)
}

/// Builds and signs an update that also deletes `stale` instances, see
/// [`build_update_removing`].
pub fn signed_update_removing(
    reg: &Registration,
    stale: &[ServiceInstance],
    key: &SrpKey,
    kind: UpdateKind,
    now: u32,
) -> Result<(Message, Vec<u8>)> {
    let mut msg = build_update_removing(reg, stale, key, kind)?;
    let wire = sign(&mut msg, key, reg.host_name()?, now)?;
    Ok((msg, wire))
}

/// Service Discovery and Service Description Instructions that delete an
/// instance: its PTR ("delete an RR from an RRset", RFC 2136 section 2.5.4)
/// and all its RRsets. Like OpenThread, subtype PTRs are left to the
/// registrar, which removes them with the instance.
fn add_service_removal(msg: &mut Message, names: &ServiceNames) {
    let mut ptr = Record::from_rdata(
        names.service.clone(),
        0,
        RData::PTR(PTR(names.instance.clone())),
    );
    ptr.set_dns_class(DNSClass::NONE);
    msg.add_update(ptr);
    msg.add_update(delete_all_rrsets(names.instance.clone()));
}

/// "Delete all RRsets from a name" (RFC 2136 section 2.5.3):
/// class ANY, type ANY, TTL 0, empty RDATA.
fn delete_all_rrsets(name: Name) -> Record {
    let mut record = Record::update0(name, 0, RecordType::ANY);
    record.set_dns_class(DNSClass::ANY);
    record
}

fn txt(entries: &[Vec<u8>]) -> TXT {
    if entries.is_empty() {
        TXT::from_bytes(vec![b"".as_slice()])
    } else {
        TXT::from_bytes(entries.iter().map(Vec::as_slice).collect())
    }
}

/// The DNS names derived from a service instance.
struct ServiceNames {
    /// `_ipp._tcp.<zone>`
    service: Name,
    /// `<instance>._ipp._tcp.<zone>`
    instance: Name,
    /// `<subtype>._sub._ipp._tcp.<zone>`
    subtypes: Vec<Name>,
}

impl ServiceNames {
    fn new(svc: &ServiceInstance, zone: &Name) -> Result<Self> {
        let service = service_type_name(&svc.service_type)?.append_domain(zone)?;
        // Raw bytes: instance labels may contain spaces, dots and UTF-8.
        let instance = Name::from_labels([svc.instance.as_bytes()])
            .map_err(|e| SrpError::invalid_name(&svc.instance, e))?
            .append_domain(&service)?;
        let subtypes = svc
            .subtypes
            .iter()
            .map(|sub| {
                if !sub.starts_with('_') {
                    return Err(SrpError::invalid_name(sub, "subtype must start with '_'"));
                }
                Ok(Name::from_labels([sub.as_bytes(), b"_sub"])
                    .map_err(|e| SrpError::invalid_name(sub, e))?
                    .append_domain(&service)?)
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            service,
            instance,
            subtypes,
        })
    }
}

/// Parses `_service._tcp` / `_service._udp`.
fn service_type_name(service_type: &str) -> Result<Name> {
    let labels: Vec<&str> = service_type.trim_end_matches('.').split('.').collect();
    match labels.as_slice() {
        [svc, proto]
            if svc.len() > 1 && svc.starts_with('_') && matches!(*proto, "_tcp" | "_udp") =>
        {
            Ok(Name::from_labels([svc.as_bytes(), proto.as_bytes()])
                .map_err(|e| SrpError::invalid_name(service_type, e))?)
        }
        _ => Err(SrpError::invalid_name(
            service_type,
            "service type must look like `_name._tcp` or `_name._udp`",
        )),
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::dnssec::Verifier;
    use hickory_proto::dnssec::rdata::DNSSECRData;
    use hickory_proto::rr::rdata::opt::EdnsCode;
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

    use super::*;
    use crate::key::SRP_KEY_FLAGS;
    use crate::lease::UPDATE_LEASE_OPTION_CODE;
    use crate::model::Host;

    fn registration() -> Registration {
        let mut svc = ServiceInstance::new("My Printer", "_ipp._tcp", 631);
        svc.subtypes.push("_universal".into());
        svc.txt.push(b"rp=ipp/print".to_vec());
        let mut reg = Registration::new(Host {
            name: "printer-42".into(),
            addresses: vec!["2001:db8::42".parse().unwrap()],
        });
        reg.services.push(svc);
        reg
    }

    /// (owner, class, type) of each record in the update section.
    fn layout(msg: &Message) -> Vec<(String, DNSClass, RecordType)> {
        msg.updates()
            .iter()
            .map(|r| (r.name().to_string(), r.dns_class(), r.record_type()))
            .collect()
    }

    #[test]
    fn register_layout() {
        let key = SrpKey::generate().unwrap();
        let msg = build_update(&registration(), &key, UpdateKind::Register).unwrap();

        assert_eq!(msg.op_code(), OpCode::Update);
        assert_eq!(msg.zones()[0].name().to_ascii(), "default.service.arpa.");
        assert_eq!(msg.zones()[0].query_type(), RecordType::SOA);
        assert!(msg.prerequisites().is_empty());

        // Compare via Name: hickory's presentation escaping is non-standard.
        let inst = Name::from_labels([b"My Printer".as_slice(), b"_ipp", b"_tcp"])
            .unwrap()
            .append_domain(&msg.zones()[0].name().clone())
            .unwrap()
            .to_string();
        let inst = inst.as_str();
        let host = "printer-42.default.service.arpa.";
        use {DNSClass as C, RecordType as T};
        let expected = [
            ("_ipp._tcp.default.service.arpa.", C::IN, T::PTR),
            (
                "_universal._sub._ipp._tcp.default.service.arpa.",
                C::IN,
                T::PTR,
            ),
            (inst, C::ANY, T::ANY),
            (inst, C::IN, T::SRV),
            (inst, C::IN, T::TXT),
            (host, C::ANY, T::ANY),
            (host, C::IN, T::AAAA),
            (host, C::IN, T::KEY),
        ];
        let expected: Vec<_> = expected
            .iter()
            .map(|(n, c, t)| (n.to_string(), *c, *t))
            .collect();
        assert_eq!(layout(&msg), expected);

        let reg = registration();
        let lease = Lease::from_message(&msg).unwrap().unwrap();
        assert_eq!(lease, Lease::new(reg.lease, reg.key_lease));
    }

    #[test]
    fn remove_layout() {
        let key = SrpKey::generate().unwrap();
        let msg = build_update(
            &registration(),
            &key,
            UpdateKind::Remove { forget_key: false },
        )
        .unwrap();
        let types: Vec<_> = layout(&msg).into_iter().map(|(_, c, t)| (c, t)).collect();
        assert_eq!(
            types,
            [
                (DNSClass::NONE, RecordType::PTR),
                (DNSClass::ANY, RecordType::ANY),
                (DNSClass::ANY, RecordType::ANY),
                (DNSClass::IN, RecordType::KEY),
            ]
        );
        let lease = Lease::from_message(&msg).unwrap().unwrap();
        assert_eq!(lease.lease, 0);
        assert_eq!(lease.key_lease(), 14 * 24 * 3600);
    }

    #[test]
    fn stale_instances_are_deleted_first() {
        let key = SrpKey::generate().unwrap();
        let mut reg = registration();
        let stale = reg.services.remove(0);
        reg.services
            .push(ServiceInstance::new("My Web", "_http._tcp", 80));
        let msg = build_update_removing(&reg, &[stale], &key, UpdateKind::Register).unwrap();
        let layout = layout(&msg);
        use {DNSClass as C, RecordType as T};
        let types: Vec<_> = layout.iter().map(|(_, c, t)| (*c, *t)).collect();
        assert_eq!(
            types,
            [
                (C::NONE, T::PTR),
                (C::ANY, T::ANY),
                (C::IN, T::PTR),
                (C::ANY, T::ANY),
                (C::IN, T::SRV),
                (C::IN, T::TXT),
                (C::ANY, T::ANY),
                (C::IN, T::AAAA),
                (C::IN, T::KEY),
            ]
        );
        assert_eq!(layout[0].0, "_ipp._tcp.default.service.arpa.");
        assert_eq!(layout[2].0, "_http._tcp.default.service.arpa.");
        // A registration, not a removal: the lease stays.
        assert_eq!(Lease::from_message(&msg).unwrap().unwrap().lease, 7200);
    }

    /// Fixed test-only P-256 key (PKCS#8), so the update bytes are reproducible.
    const GOLDEN_KEY: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
        01010420b5c68064f12364c79a4674212c02df17f433285fdf402a32b77f21d4169eef2aa144034200\
        0413a0c53753a42bb54c474b9bc6062c5d21a0cca1cb9d6594329af975ee451a1d5f3f10174a1c779e\
        2024734aba75585a4b9e50287166d9550e2fba6170dbd830";

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Public half of [`GOLDEN_KEY`], substituted for `KEY` below.
    const GOLDEN_PUB: &str = "13a0c53753a42bb54c474b9bc6062c5d21a0cca1cb9d6594329af975ee451a1d\
        5f3f10174a1c779e2024734aba75585a4b9e50287166d9550e2fba6170dbd830";

    /// Expected bytes of the update for `registration()`, record by record.
    const GOLDEN_REGISTER: &[(&str, &str)] = &[
        (
            "header: ID, UPDATE, ZO=1 PR=0 UP=8 AD=1",
            "1234 2800 0001 0000 0008 0001",
        ),
        (
            "zone: default.service.arpa. SOA IN",
            "0764656661756c74 0773657276696365 0461727061 00 0006 0001",
        ),
        (
            "_ipp._tcp PTR My\\032Printer._ipp._tcp",
            "045f697070 045f746370 c00c 000c 0001 00001c20 000d 0a4d79205072696e746572 c026",
        ),
        (
            "_universal._sub._ipp._tcp PTR (compressed target)",
            "0a5f756e6976657273616c 045f737562 c026 000c 0001 00001c20 0002 c03c",
        ),
        (
            "instance: delete all RRsets (ANY ANY, TTL 0, RDLENGTH 0)",
            "c03c 00ff 00ff 00000000 0000",
        ),
        (
            "instance SRV 0 0 631, target not compressed (RFC 2782)",
            "c03c 0021 0001 00001c20 0027 0000 0000 0277 0a7072696e7465722d3432 \
             0764656661756c74 0773657276696365 0461727061 00",
        ),
        (
            "instance TXT rp=ipp/print",
            "c03c 0010 0001 00001c20 000d 0c72703d6970702f7072696e74",
        ),
        ("host: delete all RRsets", "c085 00ff 00ff 00000000 0000"),
        (
            "host AAAA 2001:db8::42",
            "c085 001c 0001 00001c20 0010 20010db8000000000000000000000042",
        ),
        (
            "host KEY: flags 0x0201, protocol 3, algorithm 13",
            "c085 0019 0001 00001c20 0044 0201 03 0d KEY",
        ),
        (
            "OPT: udp 1232, DO, Update Lease 7200 / 1209600",
            "00 0029 04d0 00008000 000c 0002 0008 00001c20 00127500",
        ),
    ];

    /// Expected bytes of the removal with `forget_key`.
    const GOLDEN_REMOVE: &[(&str, &str)] = &[
        (
            "header: ID, UPDATE, ZO=1 PR=0 UP=4 AD=1",
            "1234 2800 0001 0000 0004 0001",
        ),
        (
            "zone: default.service.arpa. SOA IN",
            "0764656661756c74 0773657276696365 0461727061 00 0006 0001",
        ),
        (
            "_ipp._tcp PTR, class NONE, TTL 0: delete this RR",
            "045f697070 045f746370 c00c 000c 00fe 00000000 000d 0a4d79205072696e746572 c026",
        ),
        (
            "instance: delete all RRsets",
            "c03c 00ff 00ff 00000000 0000",
        ),
        (
            "host: delete all RRsets, no address adds",
            "0a7072696e7465722d3432 c00c 00ff 00ff 00000000 0000",
        ),
        ("host KEY", "c055 0019 0001 00001c20 0044 0201 03 0d KEY"),
        (
            "OPT: Update Lease 0 / 0",
            "00 0029 04d0 00008000 000c 0002 0008 00000000 00000000",
        ),
    ];

    /// Builds the unsigned update for `registration()` with ID 0x1234 and
    /// compares it with `golden`, segment by segment. SIG(0) is left out:
    /// ECDSA signatures are randomized.
    fn assert_golden(kind: UpdateKind, golden: &[(&str, &str)]) {
        let key = SrpKey::from_pkcs8(unhex(GOLDEN_KEY)).unwrap();
        let mut msg = build_update(&registration(), &key, kind).unwrap();
        msg.set_id(0x1234);
        let wire = msg.to_vec().unwrap();

        let mut rest = wire.as_slice();
        for (what, expected) in golden {
            let expected = unhex(&expected.replace("KEY", GOLDEN_PUB));
            let n = expected.len().min(rest.len());
            assert_eq!(hex(&rest[..n]), hex(&expected), "{what}");
            rest = &rest[n..];
        }
        assert!(rest.is_empty(), "trailing bytes: {}", hex(rest));
    }

    #[test]
    fn golden_register() {
        assert_golden(UpdateKind::Register, GOLDEN_REGISTER);
    }

    #[test]
    fn golden_remove() {
        assert_golden(UpdateKind::Remove { forget_key: true }, GOLDEN_REMOVE);
    }

    #[test]
    fn rejects_bad_service_type() {
        assert!(service_type_name("ipp._tcp").is_err());
        assert!(service_type_name("_ipp._sctp").is_err());
        assert!(service_type_name("_ipp").is_err());
        assert!(service_type_name("_ipp._tcp.").is_ok());
    }

    /// Verifies the SIG(0) the way a registrar does: over the received wire
    /// bytes, independent of hickory's own re-encoding.
    #[test]
    fn sig0_verifies_over_wire_bytes() {
        let key = SrpKey::generate().unwrap();
        let reg = registration();
        let (_, wire) = signed_update(&reg, &key, UpdateKind::Register, 1_700_000_000).unwrap();

        let parsed = Message::from_vec(&wire).unwrap();
        assert_eq!(parsed.sig0().len(), 1);
        let opt = parsed.extensions().as_ref().unwrap();
        assert!(opt.flags().dnssec_ok);
        assert!(
            opt.options()
                .get(EdnsCode::from(UPDATE_LEASE_OPTION_CODE))
                .is_some()
        );

        // The KEY the registrar learns from the message itself.
        let key_rr = parsed
            .updates()
            .iter()
            .find(|r| r.record_type() == RecordType::KEY)
            .unwrap();
        let RData::DNSSEC(DNSSECRData::KEY(published)) = key_rr.data() else {
            panic!("KEY rdata expected");
        };
        assert_eq!(published.flags(), SRP_KEY_FLAGS);

        let RData::DNSSEC(DNSSECRData::SIG(sig)) = parsed.sig0()[0].data() else {
            panic!("SIG rdata expected");
        };
        assert_eq!(sig.signer_name(), &reg.host_name().unwrap());
        assert_eq!(sig.type_covered(), RecordType::ZERO);

        // The SIG(0) RR must be the exact tail of the message.
        let mut sig_rr = Vec::new();
        parsed.sig0()[0]
            .emit(&mut BinEncoder::new(&mut sig_rr))
            .unwrap();
        assert!(wire.ends_with(&sig_rr));

        // RFC 2931: data = SIG RDATA (without signature) | message without SIG(0),
        // with ARCOUNT as it was before the SIG was added.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&0u16.to_be_bytes()); // type covered
        tbs.push(u8::from(sig.algorithm()));
        tbs.push(sig.num_labels());
        tbs.extend_from_slice(&sig.original_ttl().to_be_bytes());
        tbs.extend_from_slice(&sig.sig_expiration().get().to_be_bytes());
        tbs.extend_from_slice(&sig.sig_inception().get().to_be_bytes());
        tbs.extend_from_slice(&sig.key_tag().to_be_bytes());
        for label in sig.signer_name().iter() {
            tbs.push(label.len() as u8);
            tbs.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        tbs.push(0);
        let mut unsigned = wire[..wire.len() - sig_rr.len()].to_vec();
        let arcount = u16::from_be_bytes([unsigned[10], unsigned[11]]) - 1;
        unsigned[10..12].copy_from_slice(&arcount.to_be_bytes());
        tbs.extend_from_slice(&unsigned);

        published
            .verify(&tbs, sig.sig())
            .expect("signature verifies");

        // And a flipped bit in the signed part must break it.
        *tbs.last_mut().unwrap() ^= 1;
        assert!(published.verify(&tbs, sig.sig()).is_err());
    }
}
