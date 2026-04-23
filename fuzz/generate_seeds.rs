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
use std::fs;
use std::path::Path;

// Must match the engine ID used in fuzz_targets/snmpv3_request.rs.
const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80test";

const CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request";

// sysDescr.0 — a real, universally known OID, giving the fuzzer a
// concrete starting point in the MIB tree.
const SYSDESCR_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

fn main() {
    let corpus = Path::new(CORPUS_DIR);
    fs::create_dir_all(corpus).expect("failed to create corpus directory");

    let seeds: &[(&str, Vec<u8>)] = &[
        (
            "get_request",
            snmpv3_frames::encode_get_request(ENGINE_ID, b"", 1, 1, SYSDESCR_OID),
        ),
        (
            "get_next_request",
            snmpv3_frames::encode_get_next_request(ENGINE_ID, b"", 2, 2, SYSDESCR_OID),
        ),
        (
            "get_bulk_request",
            snmpv3_frames::encode_get_bulk_request(ENGINE_ID, b"", 3, 3, 0, 10, SYSDESCR_OID),
        ),
        (
            "set_request",
            snmpv3_frames::encode_set_request(ENGINE_ID, b"", 4, 4, SYSDESCR_OID),
        ),
    ];

    for (name, encoded) in seeds {
        // Verify the seed actually reaches the dispatch path before writing.
        let mut unknown_engine_ids_counter = 0u32;
        let mut unknown_user_names_counter = 0u32;
        let mut unsupported_sec_levels_counter = 0u32;
        let mut wrong_digests_counter = 0u32;
        let mut decryption_errors_counter = 0u32;
        let mut ctx = basic_snmp_agent::transport::dispatch::DispatchContext {
            engine_id: ENGINE_ID,
            engine_boots: 1,
            engine_time: 0,
            unknown_engine_ids_counter: &mut unknown_engine_ids_counter,
            unknown_user_names_counter: &mut unknown_user_names_counter,
            unsupported_sec_levels_counter: &mut unsupported_sec_levels_counter,
            wrong_digests_counter: &mut wrong_digests_counter,
            decryption_errors_counter: &mut decryption_errors_counter,
            usm_user: None,
        };
        let response =
            basic_snmp_agent::process_snmpv3_request(encoded, &mut ctx, &empty_mib());
        assert!(
            response.is_some(),
            "seed '{name}' did not produce a response — check engine ID or encoding"
        );

        let path = corpus.join(name);
        fs::write(&path, encoded)
            .unwrap_or_else(|e| panic!("failed to write seed '{name}': {e}"));
        println!("wrote {} ({} bytes) → {}", name, encoded.len(), path.display());
    }
}

fn empty_mib() -> basic_snmp_agent::mib::Store {
    basic_snmp_agent::mib::Store::new()
}
