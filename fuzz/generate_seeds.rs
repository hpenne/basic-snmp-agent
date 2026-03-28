/// Generates seed corpus files for the `snmpv3_request` fuzz target.
///
/// Each seed is a valid BER-encoded SNMPv3 message covering one inbound PDU
/// type (GetRequest, GetNextRequest, GetBulkRequest, SetRequest). Seeding the
/// corpus with structurally valid inputs lets the fuzzer skip the time it
/// would otherwise spend discovering valid BER framing from scratch and reach
/// the dispatch and MIB-lookup code paths immediately.
///
/// All seeds use the engine ID that matches the fuzz target's fixed value so
/// they exercise the full dispatch path rather than the early-discard path.
///
/// Run via `make fuzz-gen-seeds`. The corpus directory is created if absent.
use std::borrow::Cow;
use std::fs;
use std::path::Path;

use rasn::types::{OctetString, ObjectIdentifier};
use rasn_snmp::v2::{
    BulkPdu, GetBulkRequest as RasnGetBulkRequest, GetNextRequest as RasnGetNextRequest,
    GetRequest as RasnGetRequest, Pdu as RasnPdu, Pdus, SetRequest as RasnSetRequest, VarBind,
    VarBindValue as RasnVarBindValue,
};
use rasn_snmp::v3::{
    HeaderData, Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
};

// Must match the engine ID used in fuzz_targets/snmpv3_request.rs.
const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80test";

const CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request";

fn main() {
    let corpus = Path::new(CORPUS_DIR);
    fs::create_dir_all(corpus).expect("failed to create corpus directory");

    // sysDescr.0 — a real, universally known OID, giving the fuzzer a
    // concrete starting point in the MIB tree.
    let oid = oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);

    let seeds: &[(&str, Pdus)] = &[
        ("get_request", Pdus::GetRequest(get_request(1, oid.clone()))),
        (
            "get_next_request",
            Pdus::GetNextRequest(get_next_request(2, oid.clone())),
        ),
        (
            "get_bulk_request",
            Pdus::GetBulkRequest(get_bulk_request(3, oid.clone())),
        ),
        ("set_request", Pdus::SetRequest(set_request(4, oid.clone()))),
    ];

    for (name, pdus) in seeds {
        let encoded = encode_v3_message(pdus);

        // Verify the seed actually reaches the dispatch path before writing.
        let response =
            basic_snmp_agent::process_snmpv3_request(&encoded, ENGINE_ID, &empty_mib());
        assert!(
            response.is_some(),
            "seed '{name}' did not produce a response — check engine ID or encoding"
        );

        let path = corpus.join(name);
        fs::write(&path, &encoded)
            .unwrap_or_else(|e| panic!("failed to write seed '{name}': {e}"));
        println!("wrote {} ({} bytes) → {}", name, encoded.len(), path.display());
    }
}

fn empty_mib() -> basic_snmp_agent::mib::Store {
    basic_snmp_agent::mib::Store::new()
}

fn oid(arcs: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(Cow::Owned(arcs.to_vec()))
}

fn varbind(name: ObjectIdentifier) -> VarBind {
    VarBind { name, value: RasnVarBindValue::Unspecified }
}

fn pdu(request_id: i32, oid: ObjectIdentifier) -> RasnPdu {
    RasnPdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![varbind(oid)],
    }
}

fn get_request(request_id: i32, oid: ObjectIdentifier) -> RasnGetRequest {
    RasnGetRequest(pdu(request_id, oid))
}

fn get_next_request(request_id: i32, oid: ObjectIdentifier) -> RasnGetNextRequest {
    RasnGetNextRequest(pdu(request_id, oid))
}

fn get_bulk_request(request_id: i32, oid: ObjectIdentifier) -> RasnGetBulkRequest {
    RasnGetBulkRequest(BulkPdu {
        request_id,
        non_repeaters: 0,
        max_repetitions: 10,
        variable_bindings: vec![varbind(oid)],
    })
}

fn set_request(request_id: i32, oid: ObjectIdentifier) -> RasnSetRequest {
    RasnSetRequest(pdu(request_id, oid))
}

fn encode_v3_message(pdus: &Pdus) -> Vec<u8> {
    let scoped_pdu = ScopedPdu {
        engine_id: OctetString::from(ENGINE_ID.to_vec()),
        name: OctetString::from(vec![]),
        data: pdus.clone(),
    };
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: OctetString::from(vec![]),
        authoritative_engine_boots: 0.into(),
        authoritative_engine_time: 0.into(),
        user_name: OctetString::from(vec![]),
        authentication_parameters: OctetString::from(vec![]),
        privacy_parameters: OctetString::from(vec![]),
    };
    let security_parameters =
        rasn::ber::encode(&usm_params).expect("USMSecurityParameters must encode");
    let message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: 1.into(),
            max_size: 65535.into(),
            flags: OctetString::from(vec![0x04]),
            security_model: 3.into(),
        },
        security_parameters: security_parameters.into(),
        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
    };
    rasn::ber::encode(&message).expect("V3Message must encode")
}
