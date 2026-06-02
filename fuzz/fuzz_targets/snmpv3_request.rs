#![no_main]

#[path = "../fuzz_support.rs"]
mod fuzz_support;

use basic_snmp_agent::transport::dispatch::DispatchContext;
use basic_snmp_agent::transport::process_snmpv3_request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|request_bytes: &[u8]| {
    // Use a fixed engine ID; the fuzzer will explore both matching and
    // non-matching cases by varying the bytes that map to the engine ID field.
    let engine_id = b"\x80\x00\x1f\x88\x80test";
    let mut unknown_engine_ids_counter = 0u32;
    let mut unknown_user_names_counter = 0u32;
    let mut unsupported_sec_levels_counter = 0u32;
    let mut wrong_digests_counter = 0u32;
    let mut not_in_time_windows_counter = 0u32;
    let mut decryption_errors_counter = 0u32;
    let mut unknown_security_models_counter = 0u32;
    // usm_user=None with NoAuthNoPriv floor is always valid; unwrap is sound.
    let mut ctx = DispatchContext::new(
        engine_id,
        1,
        0,
        &mut unknown_engine_ids_counter,
        &mut unknown_user_names_counter,
        &mut unsupported_sec_levels_counter,
        &mut wrong_digests_counter,
        &mut not_in_time_windows_counter,
        &mut decryption_errors_counter,
        &mut unknown_security_models_counter,
        None,
        basic_snmp_agent::usm::user::SecurityLevel::NoAuthNoPriv,
    )
    .unwrap();
    let _ = process_snmpv3_request(request_bytes, &mut ctx, fuzz_support::mib());
});
