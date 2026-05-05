// Like snmpv3_request but with a USM user configured for HMAC-SHA-256 authentication,
// exercising the authentication verification and time-window check code paths.
#![no_main]

use std::sync::OnceLock;

use basic_snmp_agent::mib::Store;
use basic_snmp_agent::transport::dispatch::DispatchContext;
use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::keys::SecretKey;
use basic_snmp_agent::usm::user::{UserName, UsmUser};
use basic_snmp_agent::{Oid, Value, process_snmpv3_request};
use libfuzzer_sys::fuzz_target;

static MIB: OnceLock<Store> = OnceLock::new();
static USER: OnceLock<UsmUser> = OnceLock::new();

fn mib() -> &'static Store {
    MIB.get_or_init(|| {
        let mut store = Store::new();
        store.set(
            "1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap(),
            Value::OctetString(b"basic-snmp-agent".to_vec()),
        );
        store.set(
            "1.3.6.1.2.1.1.3.0".parse::<Oid>().unwrap(),
            Value::TimeTicks(0),
        );
        store.set(
            "1.3.6.1.2.1.1.5.0".parse::<Oid>().unwrap(),
            Value::OctetString(b"agent".to_vec()),
        );
        store.set(
            "1.3.6.1.2.1.2.1.0".parse::<Oid>().unwrap(),
            Value::Integer32(1),
        );
        store.set(
            "1.3.6.1.2.1.2.2.0".parse::<Oid>().unwrap(),
            Value::Counter32(0),
        );
        store.set(
            "1.3.6.1.2.1.2.3.0".parse::<Oid>().unwrap(),
            Value::Counter64(0),
        );
        store.set(
            "1.3.6.1.2.1.2.4.0".parse::<Oid>().unwrap(),
            Value::Gauge32(0),
        );
        store.set(
            "1.3.6.1.2.1.2.5.0".parse::<Oid>().unwrap(),
            Value::IpAddress([127, 0, 0, 1]),
        );
        store
    })
}

fn user() -> &'static UsmUser {
    USER.get_or_init(|| {
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAB; 32]);
        UsmUser::auth_no_priv(UserName::new("fuzz-user").expect("valid user name"), AuthProtocol::HmacSha256, auth_key)
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
    let _ = process_snmpv3_request(request_bytes, &mut ctx, mib());
});
