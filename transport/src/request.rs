//! SNMP request handling.
//!
//! Each inbound PDU type is resolved against a MIB store and converted to a
//! [`GetResponse`]. The logic here is intentionally free of I/O; it operates
//! purely on codec types and the MIB store, making it straightforward to unit
//! test without spinning up a socket.

use codec::{
    ErrorStatus, GetBulkRequest, GetNextRequest, GetRequest, GetResponse, Oid, SetRequest, Value,
    Varbind, VarbindValue,
};
use mib::Store;
use std::sync::LazyLock;
use std::time::Instant;

/// Lazily-initialised OID for `sysUpTime.0` (RFC 3418 §6).
///
/// Parsed once at first use rather than on every `build_wire_trap` call.
static SYS_UP_TIME_OID: LazyLock<Oid> =
    LazyLock::new(|| Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));

/// Lazily-initialised OID for `snmpTrapOID.0` (RFC 3418 §6).
///
/// Parsed once at first use rather than on every `build_wire_trap` call.
static SNMP_TRAP_OID_OID: LazyLock<Oid> =
    LazyLock::new(|| Oid::from_slice(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]));

/// The trap PDU supplied by callers to send a trap notification.
///
/// Contains only the trap OID and caller-provided varbinds. The agent
/// automatically prepends the mandatory `sysUpTime.0` and `snmpTrapOID.0`
/// varbinds before encoding per RFC 3416 §4.2.6.
///
/// This type is re-exported from the `transport` crate root and from `basic_snmp_agent`.
///
/// # Examples
///
/// ```
/// use transport::TrapPdu;
///
/// let pdu = TrapPdu {
///     request_id: 1,
///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
///     varbinds: vec![],
/// };
/// ```
#[derive(Clone, Debug)]
pub struct TrapPdu {
    /// Request identifier for correlating notifications.
    pub request_id: i32,
    /// The trap OID (`snmpTrapOID.0` value), identifying the notification type.
    pub trap_oid: Oid,
    /// Additional varbinds describing the trap payload.
    pub varbinds: Vec<Varbind>,
}

/// Handles a `GetRequest` by looking up each OID in the store.
///
/// Missing OIDs yield `NoSuchObject`; present OIDs yield their current value.
#[must_use]
pub fn handle_get(req: &GetRequest, store: &Store) -> GetResponse {
    let varbinds = req
        .varbinds
        .iter()
        .map(|vb| {
            let value = match store.get(&vb.oid) {
                Some(v) => VarbindValue::Value(v.clone()),
                None => VarbindValue::NoSuchObject,
            };
            Varbind {
                oid: vb.oid.clone(),
                value,
            }
        })
        .collect();

    GetResponse {
        request_id: req.request_id,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds,
    }
}

/// Handles a `GetNextRequest` by looking up the lexicographic successor of each OID.
///
/// If no successor exists for an OID, the varbind carries `EndOfMibView`.
#[must_use]
pub fn handle_get_next(req: &GetNextRequest, store: &Store) -> GetResponse {
    let varbinds = req
        .varbinds
        .iter()
        .map(|vb| match store.next(&vb.oid) {
            Some((next_oid, next_val)) => Varbind {
                oid: next_oid.clone(),
                value: VarbindValue::Value(next_val.clone()),
            },
            None => Varbind {
                oid: vb.oid.clone(),
                value: VarbindValue::EndOfMibView,
            },
        })
        .collect();

    GetResponse {
        request_id: req.request_id,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds,
    }
}

/// Handles a `GetBulkRequest` per RFC 3416 §4.2.3.
///
/// - The first `non_repeaters` varbinds are treated as GETNEXT (each resolved once).
/// - The remaining varbinds are repeated up to `max_repetitions` times, walking
///   forward in the MIB from each starting OID. `max_repetitions` is clamped to
///   `max_repetitions_cap`.
///
/// RFC 3416 §4.2.3 specifies that a negative `max-repetitions` on the wire must
/// be treated as zero. The `rasn-snmp` `BulkPdu` type represents both fields as
/// `u32`, and rasn rejects negative ASN.1 INTEGER values for unsigned fields with
/// a BER decode error (it decodes via the signed pair type then calls
/// `u32::try_from`, which fails for negative values). A packet with a negative
/// `max-repetitions` therefore never reaches this function; it is dropped at the
/// `decode_pdu` call site in the event loop. The cap is still applied here as a
/// defence-in-depth measure against large positive values.
#[must_use]
pub fn handle_get_bulk(
    req: &GetBulkRequest,
    store: &Store,
    max_repetitions_cap: u32,
) -> GetResponse {
    let varbind_count = req.varbinds.len();

    // Clamp non_repeaters so it cannot exceed the actual varbind count.
    let non_repeaters = (req.non_repeaters as usize).min(varbind_count);

    // Cap max_repetitions to our configurable ceiling to prevent abuse.
    let max_repetitions = req.max_repetitions.min(max_repetitions_cap);

    let mut response_varbinds: Vec<Varbind> = Vec::new();

    // Non-repeating section: resolved exactly once each, like GETNEXT.
    for vb in &req.varbinds[..non_repeaters] {
        let resolved = match store.next(&vb.oid) {
            Some((next_oid, next_val)) => Varbind {
                oid: next_oid.clone(),
                value: VarbindValue::Value(next_val.clone()),
            },
            None => Varbind {
                oid: vb.oid.clone(),
                value: VarbindValue::EndOfMibView,
            },
        };
        response_varbinds.push(resolved);
    }

    // Repeating section: each column advances max_repetitions steps forward.
    // The RFC specifies the response is ordered by repetition (all columns for
    // repetition 1, then all for repetition 2, ...).
    let repeating_varbinds = &req.varbinds[non_repeaters..];
    if !repeating_varbinds.is_empty() && max_repetitions > 0 {
        // Track the current OID for each repeating column.
        let mut current_oids: Vec<Oid> =
            repeating_varbinds.iter().map(|vb| vb.oid.clone()).collect();

        for _ in 0..max_repetitions {
            let mut all_end_of_mib = true;
            for current_oid in &mut current_oids {
                match store.next(current_oid) {
                    Some((next_oid, next_val)) => {
                        all_end_of_mib = false;
                        response_varbinds.push(Varbind {
                            oid: next_oid.clone(),
                            value: VarbindValue::Value(next_val.clone()),
                        });
                        *current_oid = next_oid.clone();
                    }
                    None => {
                        response_varbinds.push(Varbind {
                            oid: current_oid.clone(),
                            value: VarbindValue::EndOfMibView,
                        });
                    }
                }
            }
            // RFC 3416 §4.2.3: stop early once all columns have reached end of MIB.
            if all_end_of_mib {
                break;
            }
        }
    }

    GetResponse {
        request_id: req.request_id,
        error_status: ErrorStatus::NoError,
        error_index: 0,
        varbinds: response_varbinds,
    }
}

/// Handles a `SetRequest` by returning `notWritable` for all varbinds.
///
/// This agent does not support writes; all Set requests are rejected per
/// RFC 3416 with error-status `notWritable` and error-index 1.
#[must_use]
pub fn handle_set(req: &SetRequest) -> GetResponse {
    GetResponse {
        request_id: req.request_id,
        error_status: ErrorStatus::NotWritable,
        error_index: 1,
        varbinds: req.varbinds.clone(),
    }
}

/// Builds the full wire-format [`TrapPdu`] by prepending the mandatory
/// `sysUpTime.0` and `snmpTrapOID.0` varbinds before the caller-supplied payload.
///
/// Per RFC 3416 §4.2.6, every Trap-PDU must begin with these two varbinds in order.
/// The public API `TrapPdu` omits them; the event loop inserts them here so that
/// callers never have to manage `sysUpTime`.
pub fn build_wire_trap(api_pdu: &TrapPdu, start_time: Instant) -> codec::WireTrapPdu {
    let sys_up_time = elapsed_hundredths(start_time);

    let mut varbinds = vec![
        Varbind {
            oid: SYS_UP_TIME_OID.clone(),
            value: VarbindValue::Value(Value::TimeTicks(sys_up_time)),
        },
        Varbind {
            oid: SNMP_TRAP_OID_OID.clone(),
            value: VarbindValue::Value(Value::ObjectIdentifier(api_pdu.trap_oid.clone())),
        },
    ];
    varbinds.extend_from_slice(&api_pdu.varbinds);

    codec::WireTrapPdu {
        request_id: api_pdu.request_id,
        varbinds,
    }
}

/// Returns the time elapsed since `start_time` in hundredths of a second,
/// saturating at `u32::MAX`.
#[must_use]
pub(crate) fn elapsed_hundredths(start_time: Instant) -> u32 {
    let elapsed = start_time.elapsed();
    let hundredths = elapsed.as_millis() / 10;
    // Saturate at u32::MAX; the min ensures the final cast is lossless.
    u32::try_from(hundredths.min(u128::from(u32::MAX))).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn oid(s: &str) -> Oid {
        s.parse().unwrap()
    }

    fn store_with(entries: &[(&str, Value)]) -> Store {
        let mut store = Store::new();
        for (o, v) in entries {
            store.set(oid(o), v.clone());
        }
        store
    }

    // ── handle_get ────────────────────────────────────────────────────────────

    #[test]
    fn given_present_oid_when_get_then_returns_value() {
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::OctetString(b"agent".to_vec()))]);
        let req = GetRequest {
            request_id: 42,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get(&req, &store);

        assert_eq!(resp.request_id, 42);
        assert_eq!(resp.error_status, ErrorStatus::NoError);
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(
            resp.varbinds[0].value,
            VarbindValue::Value(Value::OctetString(b"agent".to_vec()))
        );
    }

    #[test]
    fn given_absent_oid_when_get_then_returns_no_such_object() {
        let store = Store::new();
        let req = GetRequest {
            request_id: 1,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get(&req, &store);

        assert_eq!(resp.varbinds[0].value, VarbindValue::NoSuchObject);
    }

    #[test]
    fn given_mixed_present_and_absent_oids_when_get_then_each_resolves_correctly() {
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetRequest {
            request_id: 5,
            varbinds: vec![
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Unspecified,
                },
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.2.0"),
                    value: VarbindValue::Unspecified,
                },
            ],
        };

        let resp = handle_get(&req, &store);

        assert_eq!(
            resp.varbinds[0].value,
            VarbindValue::Value(Value::Integer32(1))
        );
        assert_eq!(resp.varbinds[1].value, VarbindValue::NoSuchObject);
    }

    // ── handle_get_next ───────────────────────────────────────────────────────

    #[test]
    fn given_successor_exists_when_get_next_then_returns_next_oid_and_value() {
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
        ]);
        let req = GetNextRequest {
            request_id: 7,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_next(&req, &store);

        assert_eq!(resp.request_id, 7);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.2.0"));
        assert_eq!(
            resp.varbinds[0].value,
            VarbindValue::Value(Value::Integer32(2))
        );
    }

    #[test]
    fn given_no_successor_when_get_next_then_returns_end_of_mib_view() {
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetNextRequest {
            request_id: 3,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_next(&req, &store);

        assert_eq!(resp.varbinds[0].value, VarbindValue::EndOfMibView);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.1.0"));
    }

    // ── handle_get_bulk ───────────────────────────────────────────────────────

    #[test]
    fn given_bulk_request_when_non_repeaters_covers_all_then_no_repeating_section() {
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
        ]);
        let req = GetBulkRequest {
            request_id: 10,
            non_repeaters: 1,
            max_repetitions: 10,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100);

        // Only one non-repeating result.
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.2.0"));
    }

    #[test]
    fn given_bulk_request_with_repeaters_when_handled_then_walks_mib_forward() {
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
            ("1.3.6.1.2.1.1.3.0", Value::Integer32(3)),
        ]);
        let req = GetBulkRequest {
            request_id: 11,
            non_repeaters: 0,
            max_repetitions: 3,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100);

        assert_eq!(resp.varbinds.len(), 3);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.1.0"));
        assert_eq!(resp.varbinds[1].oid, oid("1.3.6.1.2.1.1.2.0"));
        assert_eq!(resp.varbinds[2].oid, oid("1.3.6.1.2.1.1.3.0"));
    }

    #[test]
    fn given_bulk_request_when_max_repetitions_exceeds_cap_then_capped() {
        let mut store = Store::new();
        for i in 0u32..200 {
            store.set(
                oid(&format!("1.3.6.1.2.1.1.{i}.0")),
                Value::Integer32(i as i32),
            );
        }
        let req = GetBulkRequest {
            request_id: 12,
            non_repeaters: 0,
            max_repetitions: 200,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 10);

        // Cap of 10 applied.
        assert_eq!(resp.varbinds.len(), 10);
    }

    #[test]
    fn given_bulk_request_when_mib_exhausted_before_max_repetitions_then_stops_early() {
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetBulkRequest {
            request_id: 13,
            non_repeaters: 0,
            max_repetitions: 10,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100);

        // Only one real entry then EndOfMibView in the second iteration — early stop.
        assert_eq!(resp.varbinds.len(), 2);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.1.0"));
        assert_eq!(resp.varbinds[1].value, VarbindValue::EndOfMibView);
    }

    // ── handle_set ────────────────────────────────────────────────────────────

    #[test]
    fn given_set_request_when_handled_then_returns_not_writable() {
        let req = SetRequest {
            request_id: 99,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Value(Value::Integer32(1)),
            }],
        };

        let resp = handle_set(&req);

        assert_eq!(resp.request_id, 99);
        assert_eq!(resp.error_status, ErrorStatus::NotWritable);
        assert_eq!(resp.error_index, 1);
    }

    // ── build_wire_trap ───────────────────────────────────────────────────────

    #[test]
    fn given_api_trap_pdu_when_built_then_prepends_sys_up_time_and_trap_oid() {
        let api_pdu = TrapPdu {
            request_id: 5,
            trap_oid: oid("1.3.6.1.6.3.1.1.5.1"),
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.5.0"),
                value: VarbindValue::Value(Value::OctetString(b"host".to_vec())),
            }],
        };
        let start = Instant::now();

        let wire = build_wire_trap(&api_pdu, start);

        assert_eq!(wire.request_id, 5);
        // First varbind must be sysUpTime.0.
        assert_eq!(wire.varbinds[0].oid, *SYS_UP_TIME_OID);
        // Second varbind must be snmpTrapOID.0 carrying the trap OID.
        assert_eq!(wire.varbinds[1].oid, *SNMP_TRAP_OID_OID);
        assert_eq!(
            wire.varbinds[1].value,
            VarbindValue::Value(Value::ObjectIdentifier(oid("1.3.6.1.6.3.1.1.5.1")))
        );
        // Remaining varbind from caller.
        assert_eq!(wire.varbinds.len(), 3);
        assert_eq!(wire.varbinds[2].oid, oid("1.3.6.1.2.1.1.5.0"));
    }

    // ── elapsed_hundredths ────────────────────────────────────────────────────

    #[test]
    fn given_start_time_just_now_when_elapsed_hundredths_then_returns_near_zero() {
        // A start time of Instant::now() has elapsed only nanoseconds, so the
        // result must be well below 5 hundredths.
        let start = Instant::now();

        let hundredths = elapsed_hundredths(start);

        assert!(hundredths < 5, "expected < 5, got {hundredths}");
    }

    #[test]
    fn given_start_time_one_second_ago_when_elapsed_hundredths_then_returns_around_100() {
        // 1 second = 100 hundredths; allow generous headroom for slow CI runners.
        let start = Instant::now() - Duration::from_secs(1);

        let hundredths = elapsed_hundredths(start);

        assert!(
            (100..=200).contains(&hundredths),
            "expected 100..=200, got {hundredths}"
        );
    }

    #[test]
    fn given_start_time_ten_seconds_ago_when_elapsed_hundredths_then_returns_around_1000() {
        // 10 seconds = 1000 hundredths; allow generous headroom for slow CI runners.
        let start = Instant::now() - Duration::from_secs(10);

        let hundredths = elapsed_hundredths(start);

        assert!(
            (1000..=1100).contains(&hundredths),
            "expected 1000..=1100, got {hundredths}"
        );
    }
}
