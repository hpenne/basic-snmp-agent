//! Test agent binary for system-level authNoPriv MIB read tests.
//!
//! Starts a `basic-snmp-agent` instance pre-seeded with a small set of known
//! MIB values and configured with a USM user requiring HMAC-SHA-256
//! authentication. Gherkin/Behave tests use this agent to exercise GET,
//! GETNEXT, and GETBULK with authNoPriv security, and to verify that requests
//! with wrong credentials are correctly rejected.
//!
//! The agent listens on port 10161 (plain TCP) and parks the main thread
//! forever once it has printed its ready message.

use basic_snmp_agent::AgentBuilder;
use basic_snmp_agent::usm::auth::AuthProtocol;

const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x04test-agent-auth";

fn main() {
    test_agent_mib_common::init_logging();

    let localised_key = basic_snmp_agent::usm::kdf::password_to_localised_key(
        b"authpassword",
        ENGINE_ID,
        AuthProtocol::HmacSha256,
    )
    .unwrap_or_else(|e| {
        eprintln!("error: failed to derive localised key: {e}");
        std::process::exit(1);
    });
    let usm_user = basic_snmp_agent::usm::user::UsmUser::auth_no_priv(
        basic_snmp_agent::usm::user::UserName::new("authuser")
            .expect("\"authuser\" is a valid user name"),
        AuthProtocol::HmacSha256,
        localised_key,
    );

    let agent = AgentBuilder::new()
        .listen_addr("0.0.0.0:10161".parse().expect("listen address is valid"))
        .engine_id(ENGINE_ID.to_vec())
        .usm_user(usm_user)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build agent: {e}");
            std::process::exit(1);
        });

    // Seed the MIB with a small, predictable set of OIDs that the system
    // tests can query by name without guessing their values.
    test_agent_mib_common::seed_test_mib(&agent, "test-agent-mib-auth");

    // Signal to the test harness that the agent is ready to accept connections.
    println!("test-agent-mib-auth ready");

    // Park the main thread indefinitely; the agent event loop runs on its own
    // thread and will continue serving requests until the process is killed.
    loop {
        std::thread::park();
    }
}
