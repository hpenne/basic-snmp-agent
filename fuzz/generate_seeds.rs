/// Generates seed corpus files for all fuzz targets.
///
/// Three categories of seeds are written:
///
/// - **SNMPv3 request seeds** (`fuzz/corpus/snmpv3_request`): valid BER-encoded SNMPv3
///   messages covering each inbound PDU type (GetRequest, GetNextRequest, GetBulkRequest,
///   SetRequest). These let the fuzzer skip the time needed to rediscover valid BER
///   framing from scratch and reach the dispatch and MIB-lookup code paths immediately.
///
/// - **TCP framing seeds** (`fuzz/corpus/tcp_framing`): raw BER length-field encodings
///   covering the short form, all valid long-form widths (1–4 octets), the indefinite-length
///   form, and an empty buffer. These seed the `tcp_framing` fuzzer that exercises
///   `parse_ber_length`.
///
/// - **Authenticated SNMPv3 request seeds** (`fuzz/corpus/snmpv3_request_auth`): SNMPv3
///   requests with a USM security header, including a seed with a correctly computed HMAC
///   that passes authentication end-to-end, as well as seeds with wrong users and missing
///   auth flags. These seed the `snmpv3_request_auth` fuzzer.
///
/// All SNMPv3 seeds use the engine ID that matches the fuzz targets' fixed value so they
/// exercise the full dispatch path rather than the early-discard path.
///
/// Run via `make fuzz-gen-seeds`. Corpus directories are created if absent.
use std::fs;
use std::path::Path;

use basic_snmp_agent::transport::dispatch::DispatchContext;

// Must match the engine ID used in fuzz_targets/snmpv3_request.rs and
// fuzz_targets/snmpv3_request_auth.rs.
const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80test";

const CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request";

// sysDescr.0 — a real, universally known OID, giving the fuzzer a
// concrete starting point in the MIB tree.
const SYSDESCR_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

// ── DispatchCounters ─────────────────────────────────────────────────────────

/// Owns the per-call USM counter variables that `DispatchContext` borrows mutably.
///
/// Constructing one of these per seed call avoids repeating six variable
/// declarations and the `DispatchContext` struct literal in each loop body.
struct DispatchCounters {
    unknown_engine_ids: u32,
    unknown_user_names: u32,
    unsupported_sec_levels: u32,
    wrong_digests: u32,
    not_in_time_windows: u32,
    decryption_errors: u32,
}

impl DispatchCounters {
    fn new() -> Self {
        Self {
            unknown_engine_ids: 0,
            unknown_user_names: 0,
            unsupported_sec_levels: 0,
            wrong_digests: 0,
            not_in_time_windows: 0,
            decryption_errors: 0,
        }
    }

    fn context<'a>(
        &'a mut self,
        usm_user: Option<&'a basic_snmp_agent::usm::user::UsmUser>,
    ) -> DispatchContext<'a> {
        DispatchContext {
            engine_id: ENGINE_ID,
            engine_boots: 1,
            engine_time: 0,
            unknown_engine_ids_counter: &mut self.unknown_engine_ids,
            unknown_user_names_counter: &mut self.unknown_user_names,
            unsupported_sec_levels_counter: &mut self.unsupported_sec_levels,
            wrong_digests_counter: &mut self.wrong_digests,
            not_in_time_windows_counter: &mut self.not_in_time_windows,
            decryption_errors_counter: &mut self.decryption_errors,
            usm_user,
        }
    }
}

// ── main ─────────────────────────────────────────────────────────────────────

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
        let mut counters = DispatchCounters::new();
        let mut ctx = counters.context(None);
        let response = basic_snmp_agent::process_snmpv3_request(encoded, &mut ctx, &empty_mib());
        assert!(
            response.is_some(),
            "seed '{name}' did not produce a response — check engine ID or encoding"
        );

        let path = corpus.join(name);
        fs::write(&path, encoded).unwrap_or_else(|e| panic!("failed to write seed '{name}': {e}"));
        println!(
            "wrote {} ({} bytes) → {}",
            name,
            encoded.len(),
            path.display()
        );
    }

    // TCP framing seeds for parse_ber_length
    let tcp_corpus = Path::new("fuzz/corpus/tcp_framing");
    fs::create_dir_all(tcp_corpus).expect("failed to create TCP framing corpus directory");

    let tcp_seeds: &[(&str, &[u8])] = &[
        ("short_form_zero", &[0x00]),
        ("short_form_max", &[0x7F]),
        ("long_form_1_octet", &[0x81, 0x80]),
        ("long_form_2_octets", &[0x82, 0x01, 0x00]),
        ("long_form_3_octets", &[0x83, 0x01, 0x00, 0x00]),
        ("long_form_4_octets", &[0x84, 0x00, 0x01, 0x00, 0x00]),
        ("indefinite_length", &[0x80]),
        ("empty", &[]),
    ];

    for (name, bytes) in tcp_seeds {
        let path = tcp_corpus.join(name);
        fs::write(&path, bytes)
            .unwrap_or_else(|e| panic!("failed to write TCP seed '{name}': {e}"));
        println!(
            "wrote {} ({} bytes) → {}",
            name,
            bytes.len(),
            path.display()
        );
    }

    // Auth fuzzer seeds
    let auth_corpus = Path::new("fuzz/corpus/snmpv3_request_auth");
    fs::create_dir_all(auth_corpus).expect("failed to create auth corpus directory");

    let auth_key_for_user =
        basic_snmp_agent::usm::keys::SecretKey::new_from_exposed_slice(&[0xAB; 32]);
    let auth_key_for_mac =
        basic_snmp_agent::usm::keys::SecretKey::new_from_exposed_slice(&[0xAB; 32]);
    let auth_user = basic_snmp_agent::usm::user::UsmUser::auth_no_priv(
        basic_snmp_agent::usm::user::UserName::new("fuzz-user").expect("valid user name"),
        basic_snmp_agent::usm::auth::AuthProtocol::HmacSha256,
        auth_key_for_user,
    );

    // Build the valid-HMAC seed: encode with zeroed auth_params, compute the
    // HMAC over that frame, then re-encode with the real MAC. Since the
    // auth_params field length is fixed at 24 bytes, the BER structure is
    // identical and only the content bytes differ.
    let zeroed_frame = snmpv3_frames::encode_get_request_with_auth_params_and_time(
        ENGINE_ID,
        b"fuzz-user",
        b"",
        10,
        10,
        SYSDESCR_OID,
        0x05,
        &[0u8; 24],
        1,
        0,
    );
    let mac = basic_snmp_agent::usm::auth::AuthProtocol::HmacSha256
        .compute_mac(&auth_key_for_mac, &zeroed_frame)
        .expect("HMAC computation failed");
    let authenticated_frame = snmpv3_frames::encode_get_request_with_auth_params_and_time(
        ENGINE_ID,
        b"fuzz-user",
        b"",
        10,
        10,
        SYSDESCR_OID,
        0x05,
        &mac,
        1,
        0,
    );

    let auth_seeds: &[(&str, Vec<u8>, bool)] = &[
        ("auth_get_request_valid_hmac", authenticated_frame, true),
        (
            "auth_get_request",
            snmpv3_frames::encode_get_request_with_auth_params_and_time(
                ENGINE_ID,
                b"fuzz-user",
                b"",
                10,
                10,
                SYSDESCR_OID,
                0x05,
                &[0u8; 24],
                1,
                0,
            ),
            false,
        ),
        (
            "auth_get_request_wrong_user",
            snmpv3_frames::encode_get_request_with_auth_params_and_time(
                ENGINE_ID,
                b"wrong-user",
                b"",
                11,
                11,
                SYSDESCR_OID,
                0x05,
                &[0u8; 24],
                1,
                0,
            ),
            false,
        ),
        (
            "noauth_get_request",
            snmpv3_frames::encode_get_request_with_user_and_flags(
                ENGINE_ID,
                b"fuzz-user",
                b"",
                12,
                12,
                SYSDESCR_OID,
                0x04,
            ),
            false,
        ),
    ];

    for (name, encoded, expect_response) in auth_seeds {
        // Verify the seed exercises the dispatch path (may produce a response or None,
        // but must not panic). Seeds with a valid HMAC must produce an actual response.
        let mut counters = DispatchCounters::new();
        let mut ctx = counters.context(Some(&auth_user));
        let response = basic_snmp_agent::process_snmpv3_request(encoded, &mut ctx, &empty_mib());
        if *expect_response {
            assert!(
                response.is_some(),
                "seed '{name}' with valid HMAC did not produce a response"
            );
        }

        let path = auth_corpus.join(name);
        fs::write(&path, encoded)
            .unwrap_or_else(|e| panic!("failed to write auth seed '{name}': {e}"));
        println!(
            "wrote {} ({} bytes) → {}",
            name,
            encoded.len(),
            path.display()
        );
    }
}

fn empty_mib() -> basic_snmp_agent::mib::Store {
    basic_snmp_agent::mib::Store::new()
}
