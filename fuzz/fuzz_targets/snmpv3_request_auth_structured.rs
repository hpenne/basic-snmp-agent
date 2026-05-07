// Like snmpv3_request_structured but with a USM user configured for
// HMAC-SHA-256 authentication, exercising the authentication verification
// and time-window check code paths with structured inputs.
#![no_main]

#[path = "../arbitrary_snmpv3.rs"]
mod arbitrary_snmpv3;

#[path = "../fuzz_support.rs"]
mod fuzz_support;

use std::sync::OnceLock;

use arbitrary_snmpv3::FuzzSnmpv3Auth;
use basic_snmp_agent::process_snmpv3_request;
use basic_snmp_agent::transport::dispatch::DispatchContext;
use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::keys::SecretKey;
use basic_snmp_agent::usm::user::{UserName, UsmUser};
use libfuzzer_sys::fuzz_target;

static USER: OnceLock<UsmUser> = OnceLock::new();

fn user() -> &'static UsmUser {
    USER.get_or_init(|| {
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAB; 32]);
        UsmUser::auth_no_priv(
            UserName::new("fuzz-user").expect("valid user name"),
            AuthProtocol::HmacSha256,
            auth_key,
        )
    })
}

fuzz_target!(|input: FuzzSnmpv3Auth| {
    let Some(encoded) = input.encode() else {
        return;
    };
    let engine_id = b"\x80\x00\x1f\x88\x80test";
    let mut unknown_engine_ids_counter = 0u32;
    let mut unknown_user_names_counter = 0u32;
    let mut unsupported_sec_levels_counter = 0u32;
    let mut wrong_digests_counter = 0u32;
    let mut not_in_time_windows_counter = 0u32;
    let mut decryption_errors_counter = 0u32;
    let mut unknown_security_models_counter = 0u32;
    let mut ctx = DispatchContext {
        engine_id,
        engine_boots: 1,
        engine_time: 0,
        unknown_engine_ids_counter: &mut unknown_engine_ids_counter,
        unknown_user_names_counter: &mut unknown_user_names_counter,
        unsupported_sec_levels_counter: &mut unsupported_sec_levels_counter,
        wrong_digests_counter: &mut wrong_digests_counter,
        not_in_time_windows_counter: &mut not_in_time_windows_counter,
        decryption_errors_counter: &mut decryption_errors_counter,
        unknown_security_models_counter: &mut unknown_security_models_counter,
        usm_user: Some(user()),
    };
    let _ = process_snmpv3_request(&encoded, &mut ctx, fuzz_support::mib());
});
