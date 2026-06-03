/// Generates seed corpus files for all fuzz targets.
///
/// Five categories of seeds are written:
///
/// - **`SNMPv3` request seeds** (`fuzz/corpus/snmpv3_request`): valid BER-encoded `SNMPv3`
///   messages covering each inbound PDU type (`GetRequest`, `GetNextRequest`, `GetBulkRequest`,
///   `SetRequest`). These let the fuzzer skip the time needed to rediscover valid BER
///   framing from scratch and reach the dispatch and MIB-lookup code paths immediately.
///
/// - **TCP framing seeds** (`fuzz/corpus/tcp_framing`): raw BER length-field encodings
///   covering the short form, all valid long-form widths (1–4 octets), the indefinite-length
///   form, and an empty buffer. These seed the `tcp_framing` fuzzer that exercises
///   `parse_ber_length`.
///
/// - **Authenticated `SNMPv3` request seeds** (`fuzz/corpus/snmpv3_request_auth`): `SNMPv3`
///   requests with a USM security header, including a seed with a correctly computed HMAC
///   that passes authentication end-to-end, as well as seeds with wrong users and missing
///   auth flags. These seed the `snmpv3_request_auth` fuzzer.
///
/// - **Structured fuzzer seeds** (`fuzz/corpus/snmpv3_request_structured` and
///   `fuzz/corpus/snmpv3_request_auth_structured`): raw byte buffers that the `Arbitrary`
///   derive deserialises into `FuzzSnmpv3` and `FuzzSnmpv3Auth` structs respectively.
///
/// - **Cross-pollinated seeds** (`fuzz/corpus/snmpv3_request` and
///   `fuzz/corpus/snmpv3_request_auth`): structured corpus entries from
///   `snmpv3_request_structured` and `snmpv3_request_auth_structured` are decoded via
///   `Arbitrary` and re-encoded as BER, then written as additional seeds for the
///   corresponding unstructured fuzzers.
///
/// All `SNMPv3` seeds use the engine ID that matches the fuzz targets' fixed value so they
/// exercise the full dispatch path rather than the early-discard path.
///
/// Run via `make fuzz-gen-seeds`. Corpus directories are created if absent.
use std::fs;
use std::path::Path;

use arbitrary::Unstructured;
use basic_snmp_agent::transport::dispatch::{DispatchContext, DispatchInputs};

#[path = "arbitrary_snmpv3.rs"]
mod arbitrary_snmpv3;

// Must match the engine ID used in fuzz_targets/snmpv3_request.rs and
// fuzz_targets/snmpv3_request_auth.rs.
const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80test";

const SNMPV3_REQUEST_CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request";
const CROSS_POLLINATED_PREFIX: &str = "structured_";
const TCP_FRAMING_CORPUS_DIR: &str = "fuzz/corpus/tcp_framing";
const AUTH_CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request_auth";
const STRUCTURED_CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request_structured";
const AUTH_STRUCTURED_CORPUS_DIR: &str = "fuzz/corpus/snmpv3_request_auth_structured";

// sysDescr.0 — a real, universally known OID, giving the fuzzer a
// concrete starting point in the MIB tree.
const SYSDESCR_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

// ── DispatchCounters ─────────────────────────────────────────────────────────

/// Owns the per-call dispatch counter variables that `DispatchContext` borrows mutably.
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
    unknown_security_models: u32,
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
            unknown_security_models: 0,
        }
    }

    fn context<'a>(
        &'a mut self,
        usm_user: Option<&'a basic_snmp_agent::usm::user::UsmUser>,
        minimum_security_level: basic_snmp_agent::usm::user::SecurityLevel,
    ) -> DispatchContext<'a> {
        // usm_user=None with NoAuthNoPriv floor and usm_user=Some with any floor are
        // always valid combinations; unwrap is sound for all seed call sites.
        DispatchContext::new(DispatchInputs {
            engine_id: ENGINE_ID,
            engine_boots: 1,
            engine_time: 0,
            unknown_engine_ids_counter: &mut self.unknown_engine_ids,
            unknown_user_names_counter: &mut self.unknown_user_names,
            unsupported_sec_levels_counter: &mut self.unsupported_sec_levels,
            wrong_digests_counter: &mut self.wrong_digests,
            not_in_time_windows_counter: &mut self.not_in_time_windows,
            decryption_errors_counter: &mut self.decryption_errors,
            unknown_security_models_counter: &mut self.unknown_security_models,
            usm_user,
            minimum_security_level,
        })
        .unwrap()
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn write_structured_seeds(corpus_dir: &Path) {
    let seeds: &[(&str, &[u8])] = &[
        ("zeros", &[0u8; 128]),
        ("ones", &[0xFF; 128]),
        (
            "ascending",
            &core::array::from_fn::<u8, 128, _>(|index| u8::try_from(index).expect("index < 128")),
        ),
    ];

    for (name, bytes) in seeds {
        let path = corpus_dir.join(name);
        fs::write(&path, bytes)
            .unwrap_or_else(|e| panic!("failed to write structured seed '{name}': {e}"));
    }
    println!(
        "wrote {} structured fuzzer seeds → {}",
        seeds.len(),
        corpus_dir.display()
    );
}

fn write_snmpv3_request_seeds(corpus: &Path) {
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
        let mut ctx = counters.context(
            None,
            basic_snmp_agent::usm::user::SecurityLevel::NoAuthNoPriv,
        );
        let response = basic_snmp_agent::transport::process_snmpv3_request(encoded, &mut ctx, &empty_mib());
        assert!(
            response.is_some(),
            "seed '{name}' did not produce a response — check engine ID or encoding"
        );

        let path = corpus.join(name);
        fs::write(&path, encoded).unwrap_or_else(|e| panic!("failed to write seed '{name}': {e}"));
    }
    println!(
        "wrote {} snmpv3_request seeds → {}",
        seeds.len(),
        corpus.display()
    );
}

fn write_tcp_framing_seeds(tcp_corpus: &Path) {
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
    }
    println!(
        "wrote {} tcp_framing seeds → {}",
        tcp_seeds.len(),
        tcp_corpus.display()
    );
}

// Build the valid-HMAC seed: encode with zeroed auth_params, compute the
// HMAC over that frame, then re-encode with the real MAC. Since the
// auth_params field length is fixed at 24 bytes, the BER structure is
// identical and only the content bytes differ.
fn build_authenticated_frame() -> Vec<u8> {
    let auth_key_for_mac =
        basic_snmp_agent::usm::keys::SecretKey::new_from_exposed_slice(&[0xAB; 32]);
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
    snmpv3_frames::encode_get_request_with_auth_params_and_time(
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
    )
}

fn write_auth_seeds(auth_corpus: &Path) {
    let auth_key_for_user =
        basic_snmp_agent::usm::keys::SecretKey::new_from_exposed_slice(&[0xAB; 32]);
    let auth_user: basic_snmp_agent::usm::user::UsmUser =
        basic_snmp_agent::usm::user::AuthNoPrivUser::new(
            basic_snmp_agent::usm::user::UserName::new("fuzz-user").expect("valid user name"),
            basic_snmp_agent::usm::auth::AuthProtocol::HmacSha256,
            auth_key_for_user,
        )
        .expect("valid key length")
        .into();

    let auth_seeds: &[(&str, Vec<u8>, bool)] = &[
        (
            "auth_get_request_valid_hmac",
            build_authenticated_frame(),
            true,
        ),
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
        let mut ctx = counters.context(
            Some(&auth_user),
            basic_snmp_agent::usm::user::SecurityLevel::AuthNoPriv,
        );
        let response = basic_snmp_agent::transport::process_snmpv3_request(encoded, &mut ctx, &empty_mib());
        if *expect_response {
            assert!(
                response.is_some(),
                "seed '{name}' with valid HMAC did not produce a response"
            );
        }

        let path = auth_corpus.join(name);
        fs::write(&path, encoded)
            .unwrap_or_else(|e| panic!("failed to write auth seed '{name}': {e}"));
    }
    println!(
        "wrote {} snmpv3_request_auth seeds → {}",
        auth_seeds.len(),
        auth_corpus.display()
    );
}

// Converts whatever is present in a structured corpus directory into
// BER-encoded seeds for the corresponding unstructured fuzzer. On a fresh run
// this is just the three synthetic bootstrap seeds written by
// `write_structured_seeds`; on subsequent runs it also includes any entries the
// structured fuzzer has accumulated from prior runs.
//
// `decode_and_encode` takes the raw corpus bytes and returns BER-encoded output,
// or an `Err` describing the failure if the entry cannot be decoded or encoded.
//
// `label` identifies the target fuzzer in log output (e.g. "snmpv3_request").
//
// Precondition: `unstructured_corpus_dir` must already exist. `main` creates it
// before calling this function.
fn cross_pollinate<F>(
    structured_corpus_dir: &Path,
    unstructured_corpus_dir: &Path,
    label: &str,
    decode_and_encode: F,
) where
    F: Fn(&[u8]) -> Result<Vec<u8>, &'static str>,
{
    let entries = match fs::read_dir(structured_corpus_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "cross-pollination ({label}): skipping — cannot read {}: {e}",
                structured_corpus_dir.display()
            );
            return;
        }
    };

    // Remove stale cross-pollinated seeds from prior runs so orphaned files do
    // not accumulate when structured corpus entries are renamed or removed.
    let existing_entries = fs::read_dir(unstructured_corpus_dir).unwrap_or_else(|e| {
        panic!(
            "failed to read {} for stale seed cleanup: {e}",
            unstructured_corpus_dir.display()
        )
    });
    for existing_entry in existing_entries {
        let existing_entry = match existing_entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("cross-pollination ({label}): skipping cleanup entry: {e}");
                continue;
            }
        };
        if existing_entry
            .file_name()
            .to_string_lossy()
            .starts_with(CROSS_POLLINATED_PREFIX)
        {
            if let Err(e) = fs::remove_file(existing_entry.path()) {
                eprintln!(
                    "cross-pollination ({label}): failed to remove stale seed {}: {e}",
                    existing_entry.file_name().to_string_lossy()
                );
            }
        }
    }

    let mut converted = 0usize;
    let mut total = 0usize;

    for dir_entry in entries {
        let dir_entry = match dir_entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("cross-pollination ({label}): skipping directory entry: {e}");
                continue;
            }
        };

        // Only process regular files; skip subdirectories and other special entries.
        if !dir_entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false)
        {
            continue;
        }

        total += 1;

        let entry_bytes = match fs::read(dir_entry.path()) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "cross-pollination ({label}): skipping {}: failed to read: {e}",
                    dir_entry.file_name().to_string_lossy()
                );
                continue;
            }
        };

        let ber_encoded = match decode_and_encode(&entry_bytes) {
            Ok(encoded) => encoded,
            Err(reason) => {
                eprintln!(
                    "cross-pollination ({label}): skipping {}: {reason}",
                    dir_entry.file_name().to_string_lossy()
                );
                continue;
            }
        };

        let original_filename = dir_entry.file_name();
        let output_filename =
            format!("{CROSS_POLLINATED_PREFIX}{}", original_filename.to_string_lossy());
        let output_path = unstructured_corpus_dir.join(&output_filename);

        fs::write(&output_path, ber_encoded).unwrap_or_else(|e| {
            panic!("failed to write cross-pollinated seed '{output_filename}': {e}")
        });

        converted += 1;
    }

    println!("cross-pollination ({label}): converted {converted} of {total} structured entries");
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let snmpv3_request_corpus = Path::new(SNMPV3_REQUEST_CORPUS_DIR);
    fs::create_dir_all(snmpv3_request_corpus).expect("failed to create corpus directory");
    write_snmpv3_request_seeds(snmpv3_request_corpus);

    let tcp_framing_corpus = Path::new(TCP_FRAMING_CORPUS_DIR);
    fs::create_dir_all(tcp_framing_corpus).expect("failed to create TCP framing corpus directory");
    write_tcp_framing_seeds(tcp_framing_corpus);

    let auth_corpus = Path::new(AUTH_CORPUS_DIR);
    fs::create_dir_all(auth_corpus).expect("failed to create auth corpus directory");
    write_auth_seeds(auth_corpus);

    let structured_corpus = Path::new(STRUCTURED_CORPUS_DIR);
    fs::create_dir_all(structured_corpus).expect("failed to create structured corpus directory");
    write_structured_seeds(structured_corpus);

    let auth_structured_corpus = Path::new(AUTH_STRUCTURED_CORPUS_DIR);
    fs::create_dir_all(auth_structured_corpus)
        .expect("failed to create auth structured corpus directory");
    write_structured_seeds(auth_structured_corpus);

    cross_pollinate(
        structured_corpus,
        snmpv3_request_corpus,
        "snmpv3_request",
        |entry_bytes| {
            let value = Unstructured::new(entry_bytes)
                .arbitrary::<arbitrary_snmpv3::FuzzSnmpv3>()
                .map_err(|_| "failed to deserialise")?;
            value.encode().ok_or("failed to encode")
        },
    );

    cross_pollinate(
        auth_structured_corpus,
        auth_corpus,
        "snmpv3_request_auth",
        |entry_bytes| {
            let value = Unstructured::new(entry_bytes)
                .arbitrary::<arbitrary_snmpv3::FuzzSnmpv3Auth>()
                .map_err(|_| "failed to deserialise")?;
            value.encode().ok_or("failed to encode")
        },
    );
}

fn empty_mib() -> basic_snmp_agent::mib::Store {
    basic_snmp_agent::mib::Store::new()
}
