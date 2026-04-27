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

use basic_snmp_agent::usm::auth::AuthProtocol;
use basic_snmp_agent::usm::user::UsmUser;
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
    let mut builder = AgentBuilder::new().listen_addr("0.0.0.0:0".parse().unwrap());

    if let Some((engine_id, usm_user)) = parse_usm_env() {
        builder = builder.engine_id(engine_id).usm_user(usm_user);
    }

    let agent = builder.build().unwrap_or_else(|e| {
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

    process::exit(i32::from(!all_ok));
}

// ── Optional USM configuration from environment ──────────────────────────────

/// Read optional USM configuration from environment variables.
///
/// Returns `Some((engine_id, usm_user))` when `USM_ENGINE_ID`, `USM_USER`,
/// `USM_AUTH_PROTO`, `USM_AUTH_PASS`, and `USM_SECURITY_LEVEL` are all set.
/// Returns `None` when none of them are set. Exits on partial or invalid config.
fn parse_usm_env() -> Option<(Vec<u8>, UsmUser)> {
    let engine_id_hex = std::env::var("USM_ENGINE_ID").ok()?;
    let user_name = std::env::var("USM_USER").unwrap_or_else(|_| {
        eprintln!("error: USM_ENGINE_ID set but USM_USER missing");
        process::exit(1);
    });
    let auth_proto_name = std::env::var("USM_AUTH_PROTO").unwrap_or_else(|_| {
        eprintln!("error: USM_ENGINE_ID set but USM_AUTH_PROTO missing");
        process::exit(1);
    });
    let auth_password = std::env::var("USM_AUTH_PASS").unwrap_or_else(|_| {
        eprintln!("error: USM_ENGINE_ID set but USM_AUTH_PASS missing");
        process::exit(1);
    });
    let security_level = std::env::var("USM_SECURITY_LEVEL").unwrap_or_else(|_| {
        eprintln!("error: USM_ENGINE_ID set but USM_SECURITY_LEVEL missing");
        process::exit(1);
    });

    let engine_id = decode_hex_engine_id(&engine_id_hex);

    let auth_protocol = match auth_proto_name.as_str() {
        "SHA-256" => AuthProtocol::HmacSha256,
        "SHA-512" => AuthProtocol::HmacSha512,
        other => {
            eprintln!("error: unsupported USM_AUTH_PROTO '{other}'");
            process::exit(1);
        }
    };

    let auth_key = basic_snmp_agent::usm::kdf::password_to_localised_key(
        auth_password.as_bytes(),
        &engine_id,
        auth_protocol,
    );

    let usm_user = match security_level.as_str() {
        "authNoPriv" => UsmUser::auth_no_priv(&user_name, auth_protocol, auth_key),
        other => {
            eprintln!("error: unsupported USM_SECURITY_LEVEL '{other}'");
            process::exit(1);
        }
    };

    Some((engine_id, usm_user))
}

/// Decode a hex-encoded engine ID string (with optional `0x` prefix) into bytes.
fn decode_hex_engine_id(hex_str: &str) -> Vec<u8> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if !hex_str.len().is_multiple_of(2) {
        eprintln!("error: USM_ENGINE_ID has odd number of hex digits");
        process::exit(1);
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|octet_start| {
            u8::from_str_radix(&hex_str[octet_start..octet_start + 2], 16).unwrap_or_else(|e| {
                eprintln!("error: invalid hex in USM_ENGINE_ID at position {octet_start}: {e}");
                process::exit(1);
            })
        })
        .collect()
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
            let raw_integer = def
                .data
                .as_i64()
                .ok_or_else(|| format!("Integer32: expected integer, got {}", def.data))?;
            i32::try_from(raw_integer)
                .map(Value::Integer32)
                .map_err(|_| format!("Integer32: value {raw_integer} is out of i32 range"))
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
            let raw_count = def.data.as_u64().ok_or_else(|| {
                format!("Counter32: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(raw_count)
                .map(Value::Counter32)
                .map_err(|_| format!("Counter32: value {raw_count} is out of u32 range"))
        }

        "Counter64" => {
            def.data.as_u64().map(Value::Counter64).ok_or_else(|| {
                format!("Counter64: expected non-negative integer, got {}", def.data)
            })
        }

        "Gauge32" => {
            let raw_gauge = def.data.as_u64().ok_or_else(|| {
                format!("Gauge32: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(raw_gauge)
                .map(Value::Gauge32)
                .map_err(|_| format!("Gauge32: value {raw_gauge} is out of u32 range"))
        }

        "TimeTicks" => {
            let raw_ticks = def.data.as_u64().ok_or_else(|| {
                format!("TimeTicks: expected non-negative integer, got {}", def.data)
            })?;
            u32::try_from(raw_ticks)
                .map(Value::TimeTicks)
                .map_err(|_| format!("TimeTicks: value {raw_ticks} is out of u32 range"))
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
            for (octet_index, octet_element) in arr.iter().enumerate() {
                let raw_octet = octet_element
                    .as_u64()
                    .ok_or_else(|| format!("IpAddress: element {octet_index} is not an integer"))?;
                octets[octet_index] = u8::try_from(raw_octet).map_err(|_| {
                    format!("IpAddress: element {octet_index} value {raw_octet} is out of u8 range")
                })?;
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
