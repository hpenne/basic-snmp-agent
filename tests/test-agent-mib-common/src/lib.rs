//! Shared test-agent MIB seeding utility for system-level MIB read tests.

use basic_snmp_agent::{Agent, Value};

/// Populate the MIB store with the fixed OIDs used by the Behave test suite.
///
/// Seeds `sysDescr.0`, `sysUpTime.0`, and `sysName.0` with values that
/// system tests can query by name without guessing their values.
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
}
