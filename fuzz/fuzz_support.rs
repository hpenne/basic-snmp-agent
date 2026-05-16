use std::sync::OnceLock;

use basic_snmp_agent::mib::Store;
use basic_snmp_agent::{Oid, Value};

static MIB: OnceLock<Store> = OnceLock::new();

pub fn mib() -> &'static Store {
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
        store.set(
            "1.3.6.1.2.1.2.6.0".parse::<Oid>().unwrap(),
            Value::ObjectIdentifier("1.3.6.1.4.1.99999".parse::<Oid>().unwrap()),
        );
        store.set(
            "1.3.6.1.2.1.2.7.0".parse::<Oid>().unwrap(),
            Value::Opaque(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        store
    })
}
