// Like snmpv3_request but with a USM user configured for HMAC-SHA-256 authentication,
// exercising the authentication verification and time-window check code paths.
#![no_main]

#[path = "../fuzz_support.rs"]
mod fuzz_support;

use std::sync::OnceLock;

use basic_snmp_agent::transport::dispatch::DispatchContext;
use basic_snmp_agent::transport::process_snmpv3_request;
use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::keys::SecretKey;
use basic_snmp_agent::usm::user::{AuthNoPrivUser, UserName, UsmUser};
use libfuzzer_sys::fuzz_target;

static USER: OnceLock<UsmUser> = OnceLock::new();

fn user() -> &'static UsmUser {
    USER.get_or_init(|| {
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAB; 32]);
        AuthNoPrivUser::new(
            UserName::new("fuzz-user").expect("valid user name"),
            AuthProtocol::HmacSha256,
            auth_key,
        )
        .expect("valid key length")
        .into()
    })
}

fuzz_target!(|request_bytes: &[u8]| {
    let engine_id = b"\x80\x00\x1f\x88\x80test";
    let mut unknown_engine_ids_counter = 0u32;
    let mut unknown_user_names_counter = 0u32;
    let mut unsupported_sec_levels_counter = 0u32;
    let mut wrong_digests_counter = 0u32;
    let mut not_in_time_windows_counter = 0u32;
    let mut decryption_errors_counter = 0u32;
    let mut unknown_security_models_counter = 0u32;
    // usm_user=Some with AuthNoPriv floor is always valid; unwrap is sound.
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
        Some(user()),
        basic_snmp_agent::usm::user::SecurityLevel::AuthNoPriv,
    )
    .unwrap();
    let _ = process_snmpv3_request(request_bytes, &mut ctx, fuzz_support::mib());
});
