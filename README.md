# basic-snmp-agent

An embeddable SNMPv3 agent library for Rust.

`basic-snmp-agent` runs a single-threaded event loop on a dedicated OS thread,
accepting inbound SNMPv3 requests over plain TCP (RFC 3430) and sending
outbound traps over UDP. Application threads interact with the agent through a
thread-safe `Agent` handle that is `Clone + Send + Sync`.

## Features

- **SNMPv3 with USM** -- User-based Security Model (RFC 3414) with
  HMAC-SHA-256/512 authentication and AES-128/256-CFB privacy.
- **Inbound request handling** -- GET, GETNEXT, GETBULK, and SET over plain
  TCP with length-prefixed framing.
- **Outbound traps** -- SNMPv2c and SNMPv3 trap PDUs sent over UDP to one or
  more destinations.
- **Push-based MIB store** -- applications call `agent.set(oid, value)` to
  publish values; the agent handles request dispatch internally.
- **No async runtime required** -- uses `mio` for I/O polling on a dedicated OS
  thread, so it drops into any application without pulling in Tokio or
  async-std.
- **Secure key handling** -- secret keys are zeroised on drop via
  `write_volatile` and `compiler_fence`.

## Quick start

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
basic-snmp-agent = { path = "." }
```

### Minimal agent with MIB entries

```rust,no_run
use basic_snmp_agent::{AgentBuilder, Oid, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build and start the agent on the default address (0.0.0.0:10161).
    let agent = AgentBuilder::new().build()?;

    // Populate some MIB entries.
    // sysDescr.0
    agent.set(
        "1.3.6.1.2.1.1.1.0".parse::<Oid>()?,
        Value::OctetString(b"basic-snmp-agent demo".to_vec()),
    )?;

    // sysUpTime.0 (TimeTicks in hundredths of a second)
    agent.set(
        "1.3.6.1.2.1.1.3.0".parse::<Oid>()?,
        Value::TimeTicks(0),
    )?;

    // sysContact.0
    agent.set(
        "1.3.6.1.2.1.1.4.0".parse::<Oid>()?,
        Value::OctetString(b"ops@example.com".to_vec()),
    )?;

    println!("Agent listening on {}", agent.local_addr());

    // The agent runs until all Agent handles are dropped.
    // Block the main thread to keep it alive.
    std::thread::park();
    Ok(())
}
```

### Sending a trap

```rust,no_run
use basic_snmp_agent::{AgentBuilder, TrapPdu, Value, Varbind, VarbindValue};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent = AgentBuilder::new().build()?;

    let trap = TrapPdu {
        request_id: 1,
        // coldStart trap OID
        trap_oid: "1.3.6.1.6.3.1.1.5.1".parse()?,
        varbinds: vec![
            Varbind {
                oid: "1.3.6.1.2.1.1.1.0".parse()?,
                value: VarbindValue::Value(Value::OctetString(b"rebooted".to_vec())),
            },
        ],
    };

    // The agent automatically prepends sysUpTime.0 and snmpTrapOID.0
    // as required by RFC 3416 section 4.2.6.
    let destination = "192.0.2.1:162".parse()?;
    let results = agent.send_trap(&trap, &[destination])?;

    for result in &results {
        match &result.outcome {
            Ok(()) => println!("Trap sent to {}", result.destination),
            Err(err) => eprintln!("Failed to send to {}: {err}", result.destination),
        }
    }

    Ok(())
}
```

### Authenticated agent (USM authNoPriv)

```rust,no_run
use basic_snmp_agent::AgentBuilder;
use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::kdf::password_to_localised_key;
use basic_snmp_agent::usm::user::{UserName, UsmUser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine_id = b"\x80\x00\x1f\x88\x04my-agent";

    // Derive a localised authentication key from a password.
    let localised_key = password_to_localised_key(
        b"my-auth-password",
        engine_id,
        AuthProtocol::HmacSha256,
    )?;

    let user = UsmUser::auth_no_priv(
        UserName::new("operator")?,
        AuthProtocol::HmacSha256,
        localised_key,
    );

    let agent = AgentBuilder::new()
        .engine_id(engine_id.to_vec())
        .usm_user(user)
        .build()?;

    println!("Authenticated agent listening on {}", agent.local_addr());
    std::thread::park();
    Ok(())
}
```

### Authenticated and encrypted agent (USM authPriv)

```rust,no_run
use basic_snmp_agent::AgentBuilder;
use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::kdf::password_to_localised_key;
use basic_snmp_agent::usm::privacy::PrivProtocol;
use basic_snmp_agent::usm::user::{UserName, UsmUser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine_id = b"\x80\x00\x1f\x88\x04my-agent";

    let localised_key = password_to_localised_key(
        b"my-auth-password",
        engine_id,
        AuthProtocol::HmacSha256,
    )?;

    // No separate privacy key needed — REQ-0084 derives it from localised_key.
    let user = UsmUser::auth_priv(
        UserName::new("secure-operator")?,
        AuthProtocol::HmacSha256,
        localised_key,
        PrivProtocol::Aes128,
    );

    let agent = AgentBuilder::new()
        .engine_id(engine_id.to_vec())
        .usm_user(user)
        .build()?;

    println!("Encrypted agent listening on {}", agent.local_addr());
    std::thread::park();
    Ok(())
}
```

## Supported SMIv2 types

The `Value` enum covers all nine standard types from RFC 2578:

| Variant             | SMIv2 type        |
|---------------------|-------------------|
| `Integer32(i32)`    | INTEGER           |
| `OctetString(Vec<u8>)` | OCTET STRING  |
| `ObjectIdentifier(Oid)` | OBJECT IDENTIFIER |
| `IpAddress([u8; 4])` | IpAddress       |
| `Counter32(u32)`    | Counter32         |
| `Counter64(u64)`    | Counter64         |
| `Gauge32(u32)`      | Gauge32           |
| `TimeTicks(u32)`    | TimeTicks         |
| `Opaque(Vec<u8>)`   | Opaque            |

## Building

```bash
cargo build
cargo test
cargo clippy --workspace --all-targets -- -W clippy::pedantic -D warnings
```

## Minimum supported Rust version

Rust 1.91 (edition 2024).

## Licence

See `LICENSE` for details.
