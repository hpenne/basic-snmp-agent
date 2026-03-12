//! Test agent binary for system-level trap tests.
//!
//! Reads a JSON trap definition file, sends each trap via [`Agent::send_trap`],
//! and prints per-destination results to stdout. Exits with code 0 if all
//! sends succeed, 1 otherwise.
//!
//! Only the public API of `basic-snmp-agent` is used; no internal crate types
//! are imported directly.
//!
//! # Usage
//!
//! ```text
//! test-agent <trap-definition-file.json>
//! ```
//!
//! # Output format
//!
//! One line per destination per trap:
//! ```text
//! OK 127.0.0.1:10162
//! ERR 127.0.0.1:10163 connection refused
//! ```

use std::net::SocketAddr;
use std::process;

use basic_snmp_agent::{AgentBuilder, Oid, TrapPdu, Value, Varbind, VarbindValue};

// ── Deserialisation types ─────────────────────────────────────────────────────

/// A single trap to send, as read from the JSON definition file.
#[derive(serde::Deserialize)]
struct TrapDefinition {
    request_id: i32,
    trap_oid: String,
    destinations: Vec<String>,
    #[serde(default)]
    varbinds: Vec<VarbindDef>,
}

/// A single varbind in a trap definition.
///
/// The `type` field names a [`Value`] variant; `data` holds the variant's
/// payload in a JSON-native representation.
#[derive(serde::Deserialize)]
struct VarbindDef {
    oid: String,
    r#type: String,
    #[serde(default)]
    data: serde_json::Value,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: test-agent <trap-definition-file.json>");
        process::exit(1);
    });

    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {path}: {e}");
        process::exit(1);
    });

    let defs: Vec<TrapDefinition> = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("error: invalid trap definition JSON: {e}");
        process::exit(1);
    });

    // Use port 0 so the OS assigns a free TCP port; no inbound requests are
    // served in this binary, but the event loop must bind a listener.
    let agent = AgentBuilder::new()
        .listen_addr("0.0.0.0:0".parse().unwrap())
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build agent: {e}");
            process::exit(1);
        });

    let mut all_ok = true;

    for def in &defs {
        let trap_oid: Oid = def.trap_oid.parse().unwrap_or_else(|e| {
            eprintln!("error: invalid trap OID '{}': {e}", def.trap_oid);
            process::exit(1);
        });

        let varbinds: Vec<Varbind> = def
            .varbinds
            .iter()
            .map(|v| {
                let oid: Oid = v.oid.parse().unwrap_or_else(|e| {
                    eprintln!("error: invalid varbind OID '{}': {e}", v.oid);
                    process::exit(1);
                });
                let value = to_value(v).unwrap_or_else(|e| {
                    eprintln!("error: invalid varbind value for OID '{}': {e}", v.oid);
                    process::exit(1);
                });
                Varbind {
                    oid,
                    value: VarbindValue::Value(value),
                }
            })
            .collect();

        let pdu = TrapPdu {
            request_id: def.request_id,
            trap_oid,
            varbinds,
        };

        let destinations: Vec<SocketAddr> = def
            .destinations
            .iter()
            .map(|d| {
                use std::net::ToSocketAddrs;
                d.to_socket_addrs()
                    .unwrap_or_else(|e| {
                        eprintln!("error: cannot resolve destination '{d}': {e}");
                        process::exit(1);
                    })
                    .next()
                    .unwrap_or_else(|| {
                        eprintln!("error: no addresses resolved for '{d}'");
                        process::exit(1);
                    })
            })
            .collect();

        match agent.send_trap(&pdu, &destinations) {
            Ok(results) => {
                for r in &results {
                    match &r.outcome {
                        Ok(()) => println!("OK {}", r.destination),
                        Err(e) => {
                            println!("ERR {} {e}", r.destination);
                            all_ok = false;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("error: send_trap failed: {e}");
                all_ok = false;
            }
        }
    }

    process::exit(if all_ok { 0 } else { 1 });
}

// ── Value conversion ──────────────────────────────────────────────────────────

/// Convert a [`VarbindDef`] into a [`Value`] instance.
///
/// Supported types (maps to `Value` variants):
/// `Integer32`, `OctetString`, `ObjectIdentifier`, `Counter32`, `Counter64`,
/// `Gauge32`, `TimeTicks`, `IpAddress`, `Opaque`.
/// If `Value` gains new variants, add them here.
fn to_value(def: &VarbindDef) -> Result<Value, String> {
    match def.r#type.as_str() {
        "Integer32" => {
            let v = def
                .data
                .as_i64()
                .ok_or_else(|| format!("Integer32: expected integer, got {}", def.data))?;
            i32::try_from(v)
                .map(Value::Integer32)
                .map_err(|_| format!("Integer32: value {v} is out of i32 range"))
        }

        "OctetString" => def
            .data
            .as_str()
            .map(|s| Value::OctetString(s.as_bytes().to_vec()))
            .ok_or_else(|| format!("OctetString: expected string, got {}", def.data)),

        "ObjectIdentifier" => def
            .data
            .as_str()
            .ok_or_else(|| format!("ObjectIdentifier: expected string, got {}", def.data))
            .and_then(|s| {
                s.parse::<Oid>()
                    .map(Value::ObjectIdentifier)
                    .map_err(|e| format!("ObjectIdentifier: invalid OID '{s}': {e}"))
            }),

        "Counter32" => {
            let v = def.data.as_u64().ok_or_else(|| {
                format!("Counter32: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(v)
                .map(Value::Counter32)
                .map_err(|_| format!("Counter32: value {v} is out of u32 range"))
        }

        "Counter64" => {
            def.data.as_u64().map(Value::Counter64).ok_or_else(|| {
                format!("Counter64: expected non-negative integer, got {}", def.data)
            })
        }

        "Gauge32" => {
            let v = def.data.as_u64().ok_or_else(|| {
                format!("Gauge32: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(v)
                .map(Value::Gauge32)
                .map_err(|_| format!("Gauge32: value {v} is out of u32 range"))
        }

        "TimeTicks" => {
            let v = def.data.as_u64().ok_or_else(|| {
                format!("TimeTicks: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(v)
                .map(Value::TimeTicks)
                .map_err(|_| format!("TimeTicks: value {v} is out of u32 range"))
        }

        "IpAddress" => {
            let arr = def
                .data
                .as_array()
                .ok_or_else(|| format!("IpAddress: expected 4-element array, got {}", def.data))?;
            if arr.len() != 4 {
                return Err(format!(
                    "IpAddress: expected exactly 4 elements, got {}",
                    arr.len()
                ));
            }
            let mut octets = [0u8; 4];
            for (i, v) in arr.iter().enumerate() {
                let n = v
                    .as_u64()
                    .ok_or_else(|| format!("IpAddress: element {i} is not an integer"))?;
                octets[i] = u8::try_from(n)
                    .map_err(|_| format!("IpAddress: element {i} value {n} is out of u8 range"))?;
            }
            Ok(Value::IpAddress(octets))
        }

        "Opaque" => def
            .data
            .as_str()
            .map(|s| Value::Opaque(s.as_bytes().to_vec()))
            .ok_or_else(|| format!("Opaque: expected string, got {}", def.data)),

        t => Err(format!("unknown value type: '{t}'")),
    }
}
