//! Test agent binary for system-level MIB read tests.
//!
//! Starts a `basic-snmp-agent` instance pre-seeded with a small set of known
//! MIB values so that Gherkin/Behave tests can exercise GET, GETNEXT, and
//! GETBULK over plain TCP without relying on external SNMP infrastructure.
//!
//! The agent listens on port 10161 (plain TCP, no TLS) and parks the main
//! thread forever once it has printed its ready message.

use basic_snmp_agent::AgentBuilder;

fn main() {
    test_agent_mib_common::init_logging();

    let agent = AgentBuilder::new()
        .listen_addr("0.0.0.0:10161".parse().expect("listen address is valid"))
        .engine_id(b"\x80\x00\x1f\x88\x04test-agent-mib".to_vec())
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build agent: {e}");
            std::process::exit(1);
        });

    // Seed the MIB with a small, predictable set of OIDs that the system
    // tests can query by name without guessing their values.
    test_agent_mib_common::seed_test_mib(&agent, "test-agent-mib");

    // Signal to the test harness that the agent is ready to accept connections.
    println!("test-agent-mib ready");

    // Park the main thread indefinitely; the agent event loop runs on its own
    // thread and will continue serving requests until the process is killed.
    loop {
        std::thread::park();
    }
}
