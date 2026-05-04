//! Shared test-agent MIB seeding utility for system-level MIB read tests.

use basic_snmp_agent::{Agent, Value};

/// Populate the MIB store with the fixed OIDs used by the Behave test suite.
///
/// Seeds `sysDescr.0`, `sysUpTime.0`, and `sysName.0` with values that
/// system tests can query by name without guessing their values.
///
/// Also seeds seven data-type coverage OIDs and a sentinel end-of-MIB OID
/// under the private enterprise subtree `1.3.6.1.4.1.99999`:
///
/// | OID                       | Type               | Value               |
/// |---------------------------|--------------------|---------------------|
/// | `1.3.6.1.4.1.99999.1.0`   | `Integer32`        | `42`                |
/// | `1.3.6.1.4.1.99999.2.0`   | `Counter32`        | `12345`             |
/// | `1.3.6.1.4.1.99999.3.0`   | `Counter64`        | `9_876_543_210`     |
/// | `1.3.6.1.4.1.99999.4.0`   | `Gauge32`          | `500`               |
/// | `1.3.6.1.4.1.99999.5.0`   | `IpAddress`        | `10.0.0.1`          |
/// | `1.3.6.1.4.1.99999.6.0`   | `ObjectIdentifier` | `1.3.6.1.4.1.99999` |
/// | `1.3.6.1.4.1.99999.7.0`   | `Opaque`           | `[0xDE, 0xAD]`      |
/// | `1.3.6.1.4.1.99999.999.0` | `Integer32`        | `0` (sentinel)      |
///
/// The sentinel OID at `.999.0` is the guaranteed last OID in the MIB, so
/// end-of-MIB GETNEXT tests remain stable as new type OIDs are added.
///
/// # Panics
///
/// Panics if any MIB entry cannot be set.
pub fn seed_test_mib(agent: &Agent, sys_name: &str) {
    agent
        .set(
            "1.3.6.1.2.1.1.1.0".parse().expect("OID is valid"),
            Value::OctetString(b"basic-snmp-agent test instance".to_vec()),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.2.1.1.3.0".parse().expect("OID is valid"),
            Value::TimeTicks(0),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.2.1.1.5.0".parse().expect("OID is valid"),
            Value::OctetString(sys_name.as_bytes().to_vec()),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.1.0".parse().expect("OID is valid"),
            Value::Integer32(42),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.2.0".parse().expect("OID is valid"),
            Value::Counter32(12345),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.3.0".parse().expect("OID is valid"),
            Value::Counter64(9_876_543_210),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.4.0".parse().expect("OID is valid"),
            Value::Gauge32(500),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.5.0".parse().expect("OID is valid"),
            Value::IpAddress([10, 0, 0, 1]),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.6.0".parse().expect("OID is valid"),
            Value::ObjectIdentifier("1.3.6.1.4.1.99999".parse().expect("OID is valid")),
        )
        .expect("MIB seed must succeed");

    agent
        .set(
            "1.3.6.1.4.1.99999.7.0".parse().expect("OID is valid"),
            Value::Opaque(vec![0xDE, 0xAD]),
        )
        .expect("MIB seed must succeed");

    // Sentinel: guaranteed last OID in the MIB so end-of-MIB tests remain
    // stable when new data-type OIDs are inserted before this subtree.
    agent
        .set(
            "1.3.6.1.4.1.99999.999.0".parse().expect("OID is valid"),
            Value::Integer32(0),
        )
        .expect("MIB seed must succeed");
}
