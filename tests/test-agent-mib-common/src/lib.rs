//! Shared test-agent MIB seeding utility and logging initialisation for system-level tests.

use basic_snmp_agent::usm::boots::{EngineBootsStore, StoredBootsState};
use basic_snmp_agent::{Agent, Value};

/// An [`EngineBootsStore`] that does no persistence.
///
/// Returns `None` on load and discards saves. Suitable for test-agent binaries
/// where boot-counter persistence is not required.
pub struct NullStore;

impl EngineBootsStore for NullStore {
    fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
        Ok(None)
    }
    fn save(&mut self, _: &[u8], _: u32) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// A minimal logger that writes to stderr, used by test agent binaries.
struct StderrLogger {
    level_filter: log::LevelFilter,
}

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level_filter
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{} {}] {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Initialise stderr logging for test agent binaries.
///
/// Reads the `RUST_LOG` environment variable and parses it as a log level name
/// (case-insensitive). Recognised values are `off`, `error`, `warn`, `info`,
/// `debug`, and `trace`. If the variable is unset or contains an unrecognised
/// value, logging is disabled (`LevelFilter::Off`).
///
/// # Panics
///
/// Panics if a logger has already been installed in the current process.
pub fn init_logging() {
    let level_filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level_name| level_name.parse().ok())
        .unwrap_or(log::LevelFilter::Off);

    // log::set_logger requires a &'static reference; Box::leak provides one.
    let logger = Box::leak(Box::new(StderrLogger { level_filter }));
    log::set_logger(logger).expect("logger must not already be set in test agents");
    log::set_max_level(level_filter);
}

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
