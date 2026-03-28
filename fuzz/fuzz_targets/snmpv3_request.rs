#![no_main]

use std::sync::OnceLock;

use basic_snmp_agent::mib::Store;
use basic_snmp_agent::{Oid, Value, process_snmpv3_request};
use libfuzzer_sys::fuzz_target;

// Pre-populated MIB store shared across all fuzz iterations.
// Using OnceLock avoids rebuilding the store on every call.
static MIB: OnceLock<Store> = OnceLock::new();

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

fuzz_target!(|data: &[u8]| {
    // Use a fixed engine ID; the fuzzer will explore both matching and
    // non-matching cases by varying the bytes that map to the engine ID field.
    let engine_id = b"\x80\x00\x1f\x88\x80test";
    let _ = process_snmpv3_request(data, engine_id, mib());
});
