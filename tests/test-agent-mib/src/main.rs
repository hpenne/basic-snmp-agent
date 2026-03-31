//! Test agent binary for system-level MIB read tests.
//!
//! Starts a `basic-snmp-agent` instance pre-seeded with a small set of known
//! MIB values so that Gherkin/Behave tests can exercise GET, GETNEXT, and
//! GETBULK over TLS with mutual authentication, without relying on external
//! SNMP infrastructure.
//!
//! The agent listens on port 10161 with TLS (mutual authentication) and parks
//! the main thread forever once it has printed its ready message.

use basic_snmp_agent::{AgentBuilder, Value};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn load_tls_config(
    cert_dir: &std::path::Path,
) -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<CertificateDer<'static>>,
) {
    let server_cert_pem = std::fs::read(cert_dir.join("server.crt")).unwrap_or_else(|e| {
        eprintln!("error: failed to read server.crt: {e}");
        std::process::exit(1);
    });
    let server_cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut server_cert_pem.as_slice())
            .map(|result| {
                result.unwrap_or_else(|e| {
                    eprintln!("error: failed to parse server.crt: {e}");
                    std::process::exit(1);
                })
            })
            .collect();

    let server_key_pem = std::fs::read(cert_dir.join("server.key")).unwrap_or_else(|e| {
        eprintln!("error: failed to read server.key: {e}");
        std::process::exit(1);
    });
    let private_key =
        rustls_pemfile::private_key(&mut server_key_pem.as_slice())
            .unwrap_or_else(|e| {
                eprintln!("error: failed to parse server.key: {e}");
                std::process::exit(1);
            })
            .unwrap_or_else(|| {
                eprintln!("error: server.key contains no private key");
                std::process::exit(1);
            });

    let ca_pem = std::fs::read(cert_dir.join("ca.crt")).unwrap_or_else(|e| {
        eprintln!("error: failed to read ca.crt: {e}");
        std::process::exit(1);
    });
    let ca_trust_anchors: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_pem.as_slice())
            .map(|result| {
                result.unwrap_or_else(|e| {
                    eprintln!("error: failed to parse ca.crt: {e}");
                    std::process::exit(1);
                })
            })
            .collect();

    (server_cert_chain, private_key, ca_trust_anchors)
}

fn main() {
    let cert_dir_str = std::env::var("CERT_DIR").unwrap_or_else(|_| "/certs".to_string());
    let cert_dir = std::path::Path::new(&cert_dir_str);
    let (server_cert_chain, private_key, ca_trust_anchors) = load_tls_config(cert_dir);

    let agent = AgentBuilder::new()
        .listen_addr("0.0.0.0:10161".parse().expect("listen address is valid"))
        .engine_id(b"\x80\x00\x1f\x88\x04test-agent-mib".to_vec())
        .server_cert_chain(server_cert_chain)
        .server_private_key(private_key)
        .ca_trust_anchors(ca_trust_anchors)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build agent: {e}");
            std::process::exit(1);
        });

    // Seed the MIB with a small, predictable set of OIDs that the system
    // tests can query by name without guessing their values.
    seed_mib(&agent);

    // Signal to the test harness that the agent is ready to accept connections.
    println!("test-agent-mib ready");

    // Park the main thread indefinitely; the agent event loop runs on its own
    // thread and will continue serving requests until the process is killed.
    loop {
        std::thread::park();
    }
}

/// Populate the MIB store with the fixed OIDs used by the Behave test suite.
fn seed_mib(agent: &basic_snmp_agent::Agent) {
    // sysDescr.0 — human-readable system description.
    agent
        .set(
            "1.3.6.1.2.1.1.1.0".parse().expect("OID is valid"),
            Value::OctetString(b"basic-snmp-agent test instance".to_vec()),
        )
        .expect("MIB seed must succeed");

    // sysUpTime.0 — time since last re-initialisation (static for tests).
    agent
        .set(
            "1.3.6.1.2.1.1.3.0".parse().expect("OID is valid"),
            Value::TimeTicks(0),
        )
        .expect("MIB seed must succeed");

    // sysName.0 — administratively assigned name for this node.
    agent
        .set(
            "1.3.6.1.2.1.1.5.0".parse().expect("OID is valid"),
            Value::OctetString(b"test-agent-mib".to_vec()),
        )
        .expect("MIB seed must succeed");
}
