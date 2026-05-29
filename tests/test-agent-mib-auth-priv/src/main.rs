//! Test agent binary for system-level authPriv MIB read tests.
//!
//! Starts a `basic-snmp-agent` instance pre-seeded with a small set of known
//! MIB values and configured with a USM user requiring HMAC-SHA-256
//! authentication and AES-128-CFB privacy. Gherkin/Behave tests use this agent
//! to exercise GET, GETNEXT, and GETBULK with authPriv security, and to verify
//! that requests with wrong credentials or insufficient security level are
//! correctly rejected.
//!
//! The agent listens on port 10161 (plain TCP) and parks the main thread
//! forever once it has printed its ready message.

use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::privacy::PrivProtocol;
use basic_snmp_agent::usm::user::UserName;
use basic_snmp_agent::{AgentBuilder, AuthPrivUser, SecurityConfig};

const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x04test-agent-priv";

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
    let user = AuthPrivUser::new(
        UserName::new("privuser").expect("\"privuser\" is a valid user name"),
        AuthProtocol::HmacSha256,
        localised_key,
        PrivProtocol::Aes128,
    )
    .unwrap_or_else(|e| {
        eprintln!("error: failed to create USM user: {e}");
        std::process::exit(1);
    });

    let agent = AgentBuilder::new(SecurityConfig::AuthPriv {
        user,
        boots_store: Box::new(test_agent_mib_common::NullStore),
    })
    .listen_addr("0.0.0.0:10161".parse().expect("listen address is valid"))
    .engine_id(ENGINE_ID.to_vec())
    .build()
    .unwrap_or_else(|e| {
        eprintln!("error: failed to build agent: {e}");
        std::process::exit(1);
    });

    // Seed the MIB with a small, predictable set of OIDs that the system
    // tests can query by name without guessing their values.
    test_agent_mib_common::seed_test_mib(&agent, "test-agent-mib-auth-priv");

    // Signal to the test harness that the agent is ready to accept connections.
    println!("test-agent-mib-auth-priv ready");

    // Park the main thread indefinitely; the agent event loop runs on its own
    // thread and will continue serving requests until the process is killed.
    loop {
        std::thread::park();
    }
}
