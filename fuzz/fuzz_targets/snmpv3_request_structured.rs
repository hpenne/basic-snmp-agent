#![no_main]

#[path = "../arbitrary_snmpv3.rs"]
mod arbitrary_snmpv3;

#[path = "../fuzz_support.rs"]
mod fuzz_support;

use arbitrary_snmpv3::FuzzSnmpv3;
use basic_snmp_agent::transport::dispatch::{DispatchContext, DispatchInputs};
use basic_snmp_agent::transport::process_snmpv3_request;
use basic_snmp_agent::usm::counters::UsmStatsCounter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzSnmpv3| {
    let Some(encoded) = input.encode() else {
        return;
    };
    let engine_id = b"\x80\x00\x1f\x88\x80test";
    let mut unknown_engine_ids_counter = UsmStatsCounter::default();
    let mut unknown_user_names_counter = UsmStatsCounter::default();
    let mut unsupported_sec_levels_counter = UsmStatsCounter::default();
    let mut wrong_digests_counter = UsmStatsCounter::default();
    let mut not_in_time_windows_counter = UsmStatsCounter::default();
    let mut decryption_errors_counter = UsmStatsCounter::default();
    let mut unknown_security_models_counter = UsmStatsCounter::default();
    // usm_user=None with NoAuthNoPriv floor is always valid; unwrap is sound.
    let mut ctx = DispatchContext::new(DispatchInputs {
        engine_id,
        engine_boots: basic_snmp_agent::usm::engine_time::EngineBoots::from(1_u32),
        engine_time: basic_snmp_agent::usm::engine_time::EngineTime::ZERO,
        unknown_engine_ids_counter: &mut unknown_engine_ids_counter,
        unknown_user_names_counter: &mut unknown_user_names_counter,
        unsupported_sec_levels_counter: &mut unsupported_sec_levels_counter,
        wrong_digests_counter: &mut wrong_digests_counter,
        not_in_time_windows_counter: &mut not_in_time_windows_counter,
        decryption_errors_counter: &mut decryption_errors_counter,
        unknown_security_models_counter: &mut unknown_security_models_counter,
        usm_user: None,
        minimum_security_level: basic_snmp_agent::usm::user::SecurityLevel::NoAuthNoPriv,
    })
    .unwrap();
    let _ = process_snmpv3_request(&encoded, &mut ctx, fuzz_support::mib());
});
