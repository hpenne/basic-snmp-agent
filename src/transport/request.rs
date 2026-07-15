//! SNMP request handling.
//!
//! Each inbound PDU type is resolved against a MIB store and converted to a
//! [`GetResponse`]. The logic here is intentionally free of I/O; it operates
//! purely on codec types and the MIB store, making it straightforward to unit
//! test without spinning up a socket.

use crate::codec::{
    ErrorStatus, GetBulkRequest, GetNextRequest, GetRequest, GetResponse, Oid, RequestId,
    SetRequest, Value, Varbind, VarbindValue,
};
use crate::mib::Store;
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
/// This type is re-exported from the crate root via `basic_snmp_agent`.
///
/// # Requirements
/// Implements: REQ-0039, REQ-0040
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::{RequestId, TrapPdu};
///
/// let pdu = TrapPdu {
///     request_id: RequestId::from(1),
///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
///     varbinds: vec![],
/// };
/// ```
#[derive(Clone, Debug)]
pub struct TrapPdu {
    /// Request identifier for correlating notifications.
    pub request_id: RequestId,
    /// The trap OID (`snmpTrapOID.0` value), identifying the notification type.
    pub trap_oid: Oid,
    /// Additional varbinds describing the trap payload.
    pub varbinds: Vec<Varbind>,
}

/// Handles a `GetRequest` by looking up each OID in the store.
///
/// Missing OIDs yield `NoSuchObject`; present OIDs yield their current value.
///
/// # Requirements
/// Implements: REQ-0021, REQ-0022, REQ-0023, REQ-0066
#[must_use]
pub fn handle_get(req: &GetRequest, store: &Store) -> GetResponse {
    let varbinds = req
        .varbinds
        .iter()
        .map(|vb| {
            let value = store.get(&vb.oid).map_or(VarbindValue::NoSuchObject, |v| {
                VarbindValue::Value(v.clone())
            });
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
///
/// # Requirements
/// Implements: REQ-0021, REQ-0022, REQ-0024, REQ-0025, REQ-0066
#[must_use]
pub fn handle_get_next(req: &GetNextRequest, store: &Store) -> GetResponse {
    let varbinds = req
        .varbinds
        .iter()
        .map(|vb| resolve_get_next_varbind(store, &vb.oid))
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
/// - The response is bounded to `max_response_size` bytes by estimating the
///   wire size of accumulated varbinds. When the budget would be exceeded, the
///   repeating section is truncated at a complete row boundary per RFC 3416 §4.2.3.
///
/// RFC 3416 §4.2.3 specifies that a negative `max-repetitions` on the wire must
/// be treated as zero. The `rasn-snmp` `BulkPdu` type represents both fields as
/// `u32`, and rasn rejects negative ASN.1 INTEGER values for unsigned fields with
/// a BER decode error (it decodes via the signed pair type then calls
/// `u32::try_from`, which fails for negative values). A packet with a negative
/// `max-repetitions` therefore never reaches this function; it is dropped at the
/// `decode_pdu` call site in the event loop. The cap is still applied here as a
/// defence-in-depth measure against large positive values.
///
/// # Requirements
/// Implements: REQ-0021, REQ-0022, REQ-0024, REQ-0025, REQ-0026, REQ-0027, REQ-0028, REQ-0029, REQ-0030, REQ-0031, REQ-0066, REQ-0133, REQ-0134
#[must_use]
pub fn handle_get_bulk(
    req: &GetBulkRequest,
    store: &Store,
    max_repetitions_cap: u32,
    max_response_size: usize,
) -> GetResponse {
    let varbind_count = req.varbinds.len();

    // Clamp non_repeaters so it cannot exceed the actual varbind count.
    let non_repeaters = usize::try_from(req.non_repeaters)
        .unwrap_or(usize::MAX)
        .min(varbind_count);

    // Cap max_repetitions to our configurable ceiling to prevent abuse.
    let max_repetitions = req.max_repetitions.min(max_repetitions_cap);

    // REQ-0133: budget for varbind wire bytes after subtracting the envelope overhead.
    let varbind_budget = max_response_size.saturating_sub(V3_ENVELOPE_OVERHEAD);

    let mut response_varbinds: Vec<Varbind> = Vec::new();
    let mut estimated_response_size: usize = 0;

    // Non-repeating section: resolved exactly once each, like GETNEXT.
    let (non_repeating_varbinds, repeating_varbinds) = req.varbinds.split_at(non_repeaters);
    for vb in non_repeating_varbinds {
        let resolved = resolve_get_next_varbind(store, &vb.oid);
        estimated_response_size += estimated_varbind_wire_size(&resolved);
        response_varbinds.push(resolved);
    }

    // Repeating section: each column advances max_repetitions steps forward.
    // The RFC specifies the response is ordered by repetition (all columns for
    // repetition 1, then all for repetition 2, ...).
    if !repeating_varbinds.is_empty() && max_repetitions > 0 {
        // Track the current OID for each repeating column.
        let mut current_oids: Vec<Oid> =
            repeating_varbinds.iter().map(|vb| vb.oid.clone()).collect();

        for _ in 0..max_repetitions {
            // Collect the entire row before committing any of it, so truncation
            // always falls on a complete row boundary (REQ-0134).
            let row = build_repeating_row(store, &mut current_oids);

            // REQ-0133, REQ-0134: check size budget before committing this row.
            if estimated_response_size + row.estimated_size > varbind_budget {
                break;
            }

            estimated_response_size += row.estimated_size;
            response_varbinds.extend(row.varbinds);

            // RFC 3416 §4.2.3: stop early once all columns have reached end of MIB.
            if row.all_end_of_mib {
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

/// One row of a `GetBulkRequest` repeating section: the varbinds produced by
/// advancing every repeating column one step, their combined estimated wire
/// size, and whether every column has reached `EndOfMibView`.
///
/// Bundled into one type because `handle_get_bulk` always needs all three
/// together: the size to weigh against the budget, the varbinds to commit if
/// it fits, and the early-exit signal once nothing more can be produced.
// Implements: REQ-0133, REQ-0134
struct RepeatingRow {
    varbinds: Vec<Varbind>,
    estimated_size: usize,
    all_end_of_mib: bool,
}

/// Advances every repeating column in `current_oids` one step forward and
/// builds the resulting row, mutating `current_oids` in place to the new
/// positions.
///
/// A column that has already reached `EndOfMibView` is left unchanged, since
/// `Store::next` on a terminal OID keeps returning `None`.
// Implements: REQ-0024, REQ-0025, REQ-0026, REQ-0066, REQ-0133, REQ-0134
fn build_repeating_row(store: &Store, current_oids: &mut [Oid]) -> RepeatingRow {
    let mut row_varbinds: Vec<Varbind> = Vec::with_capacity(current_oids.len());
    let mut row_estimated_size: usize = 0;
    let mut all_end_of_mib = true;

    for current_oid in current_oids {
        let resolved = resolve_get_next_varbind(store, current_oid);
        if let VarbindValue::Value(_) = &resolved.value {
            all_end_of_mib = false;
            *current_oid = resolved.oid.clone();
        }
        row_estimated_size += estimated_varbind_wire_size(&resolved);
        row_varbinds.push(resolved);
    }

    RepeatingRow {
        varbinds: row_varbinds,
        estimated_size: row_estimated_size,
        all_end_of_mib,
    }
}

/// Resolves a single OID to its GETNEXT-style successor varbind: the
/// lexicographic next OID and value if one exists, or `EndOfMibView` if
/// `oid` is the last OID in the store.
///
/// Shared by the non-repeating section and each row of the repeating section
/// of `handle_get_bulk`, both of which perform exactly this per-OID step.
// Implements: REQ-0021, REQ-0024, REQ-0025, REQ-0066
fn resolve_get_next_varbind(store: &Store, oid: &Oid) -> Varbind {
    match store.next(oid) {
        Some((next_oid, next_value)) => Varbind {
            oid: next_oid.clone(),
            value: VarbindValue::Value(next_value.clone()),
        },
        None => Varbind {
            oid: oid.clone(),
            value: VarbindValue::EndOfMibView,
        },
    }
}

/// Generous fixed overhead for the `SNMPv3` message envelope surrounding
/// the varbind list: outer SEQUENCE, version, `HeaderData`, USM security
/// parameters (with auth+priv placeholders), `ScopedPdu` headers, and
/// Response PDU headers (tag, length, request-id, error-status, error-index,
/// varbind-list SEQUENCE wrapper).
///
/// Breakdown: outer SEQUENCE (~4), version INTEGER (3), `HeaderData` (~30),
/// USM security parameters OCTET STRING (~100 with auth+priv),
/// `ScopedPdu` SEQUENCE + context fields (~20), Response PDU headers (~15),
/// varbind-list SEQUENCE wrapper (~4). Total ≈ 176 bytes; 512 provides
/// a factor-of-three safety margin.
// Implements: REQ-0133
const V3_ENVELOPE_OVERHEAD: usize = 512;

/// Upper-bound estimate of a varbind's BER-encoded wire size.
///
/// Deliberately overestimates to avoid ever producing a response that
/// exceeds the negotiated message size limit. Overestimation is safe:
/// the agent returns fewer rows than it could, which is compliant with
/// RFC 3416 §4.2.3.
// Implements: REQ-0133
fn estimated_varbind_wire_size(varbind: &Varbind) -> usize {
    let oid_content_upper_bound = varbind.oid.as_slice().len() * 5;
    let oid_tlv_size = 1 + length_of_length(oid_content_upper_bound) + oid_content_upper_bound;

    let value_content_upper_bound = match &varbind.value {
        VarbindValue::Value(Value::Integer32(_) | Value::IpAddress(_)) => 4,
        VarbindValue::Value(Value::Counter32(_) | Value::Gauge32(_) | Value::TimeTicks(_)) => 5,
        VarbindValue::Value(Value::Counter64(_)) => 9,
        VarbindValue::Value(Value::OctetString(octets) | Value::Opaque(octets)) => octets.len(),
        VarbindValue::Value(Value::ObjectIdentifier(oid)) => oid.as_slice().len() * 5,
        VarbindValue::NoSuchObject
        | VarbindValue::NoSuchInstance
        | VarbindValue::EndOfMibView
        | VarbindValue::Unspecified => 0,
    };
    let value_tlv_size =
        1 + length_of_length(value_content_upper_bound) + value_content_upper_bound;

    // Wrapping SEQUENCE: tag(1) + length + contents
    let inner_size = oid_tlv_size + value_tlv_size;
    1 + length_of_length(inner_size) + inner_size
}

/// Returns the number of bytes required by BER definite-length encoding for
/// a field whose content is `content_length` bytes long.
///
/// Used for conservative size estimation in `estimated_varbind_wire_size`: the
/// estimate must never undercount, so this function must account for all
/// possible BER length encodings including those above 65535 bytes.
///
/// BER short form: 1 byte for lengths 0–127. BER long form: 1 indicator byte
/// plus the minimum number of bytes needed to represent the length value.
// Implements: REQ-0133
fn length_of_length(content_length: usize) -> usize {
    if content_length < 128 {
        1
    } else {
        // BER long form: 1 indicator byte + the minimum number of bytes
        // needed to encode the length value.
        let significant_bytes = (usize::BITS - content_length.leading_zeros()).div_ceil(8);
        1 + usize::from(u8::try_from(significant_bytes).unwrap_or(u8::MAX))
    }
}

/// Handles a `SetRequest` by returning `notWritable` for all varbinds.
///
/// This agent does not support writes; all Set requests are rejected per
/// RFC 3416 with error-status `notWritable` and error-index 1.
///
/// # Requirements
/// Implements: REQ-0032
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
///
/// # Requirements
/// Implements: REQ-0037, REQ-0038, REQ-0041
pub fn build_wire_trap(api_pdu: &TrapPdu, start_time: Instant) -> crate::codec::WireTrapPdu {
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

    crate::codec::WireTrapPdu {
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
        // Verifies: REQ-0021, REQ-0022, REQ-0066
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::OctetString(b"agent".to_vec()))]);
        let req = GetRequest {
            request_id: RequestId::from(42),
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get(&req, &store);

        assert_eq!(resp.request_id, RequestId::from(42));
        assert_eq!(resp.error_status, ErrorStatus::NoError);
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(
            resp.varbinds[0].value,
            VarbindValue::Value(Value::OctetString(b"agent".to_vec()))
        );
    }

    #[test]
    fn given_absent_oid_when_get_then_returns_no_such_object() {
        // Verifies: REQ-0023
        let store = Store::new();
        let req = GetRequest {
            request_id: RequestId::from(1),
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
        // Verifies: REQ-0021, REQ-0022, REQ-0023
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetRequest {
            request_id: RequestId::from(5),
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
        // Verifies: REQ-0021, REQ-0022, REQ-0024, REQ-0066
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
        ]);
        let req = GetNextRequest {
            request_id: RequestId::from(7),
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_next(&req, &store);

        assert_eq!(resp.request_id, RequestId::from(7));
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.2.0"));
        assert_eq!(
            resp.varbinds[0].value,
            VarbindValue::Value(Value::Integer32(2))
        );
    }

    #[test]
    fn given_no_successor_when_get_next_then_returns_end_of_mib_view() {
        // Verifies: REQ-0024, REQ-0025
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetNextRequest {
            request_id: RequestId::from(3),
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
        // Verifies: REQ-0026, REQ-0027
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
        ]);
        let req = GetBulkRequest {
            request_id: RequestId::from(10),
            non_repeaters: 1,
            max_repetitions: 10,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);

        // Only one non-repeating result.
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.2.0"));
    }

    #[test]
    fn given_bulk_request_with_repeaters_when_handled_then_walks_mib_forward() {
        // Verifies: REQ-0021, REQ-0022, REQ-0026, REQ-0066
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
            ("1.3.6.1.2.1.1.3.0", Value::Integer32(3)),
        ]);
        let req = GetBulkRequest {
            request_id: RequestId::from(11),
            non_repeaters: 0,
            max_repetitions: 3,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);

        assert_eq!(resp.varbinds.len(), 3);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.1.0"));
        assert_eq!(resp.varbinds[1].oid, oid("1.3.6.1.2.1.1.2.0"));
        assert_eq!(resp.varbinds[2].oid, oid("1.3.6.1.2.1.1.3.0"));
    }

    #[test]
    fn given_bulk_request_when_max_repetitions_exceeds_cap_then_capped() {
        // Verifies: REQ-0029, REQ-0030, REQ-0031
        let mut store = Store::new();
        for i in 0_u32..200 {
            store.set(
                oid(&format!("1.3.6.1.2.1.1.{i}.0")),
                Value::Integer32(i.cast_signed()),
            );
        }
        let req = GetBulkRequest {
            request_id: RequestId::from(12),
            non_repeaters: 0,
            max_repetitions: 200,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 10, 0xFFFF);

        // Cap of 10 applied.
        assert_eq!(resp.varbinds.len(), 10);
    }

    #[test]
    fn given_bulk_request_when_mib_exhausted_before_max_repetitions_then_stops_early() {
        // Verifies: REQ-0024, REQ-0026
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetBulkRequest {
            request_id: RequestId::from(13),
            non_repeaters: 0,
            max_repetitions: 10,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);

        // Only one real entry then EndOfMibView in the second iteration — early stop.
        assert_eq!(resp.varbinds.len(), 2);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.1.0"));
        assert_eq!(resp.varbinds[1].value, VarbindValue::EndOfMibView);
    }

    #[test]
    fn given_empty_mib_when_get_bulk_then_all_end_of_mib_view() {
        // Verifies: REQ-0025
        let store = Store::new();
        let req = GetBulkRequest {
            request_id: RequestId::from(1),
            non_repeaters: 0,
            max_repetitions: 3,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };
        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);
        // RFC 3416 §4.2.3: stop early when all columns have reached end of MIB.
        // With an empty MIB the first repetition exhausts all columns immediately,
        // so the response contains exactly one EndOfMibView varbind.
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(resp.varbinds[0].value, VarbindValue::EndOfMibView);
    }

    #[test]
    fn given_bulk_request_when_max_repetitions_zero_then_only_non_repeaters_returned() {
        // Verifies: REQ-0027
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetBulkRequest {
            request_id: RequestId::from(2),
            non_repeaters: 1,
            max_repetitions: 0,
            varbinds: vec![
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Unspecified,
                },
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Unspecified,
                },
            ],
        };
        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);
        // Only the non-repeater varbind (GETNEXT of first OID) should appear.
        assert_eq!(resp.varbinds.len(), 1);
    }

    #[test]
    fn given_bulk_request_when_non_repeaters_zero_and_max_repetitions_zero_then_no_varbinds() {
        // Verifies: REQ-0026, REQ-0027
        // Regression guard for RFC 3416 §4.2.3 semantics: max_repetitions=0 must
        // produce an empty repeating section. The `&& → ||` and `> → >=` mutants
        // at this condition produce identical output for this input; see
        // .cargo/mutants.toml for the suppression rationale.
        let store = store_with(&[("1.3.6.1.2.1.1.1.0", Value::Integer32(1))]);
        let req = GetBulkRequest {
            request_id: RequestId::from(3),
            non_repeaters: 0,
            max_repetitions: 0,
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Unspecified,
            }],
        };

        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);

        // No non-repeaters and no repetitions: the response must be empty.
        assert_eq!(
            resp.varbinds.len(),
            0,
            "expected empty response when max_repetitions=0 and non_repeaters=0"
        );
    }

    // ── handle_set ────────────────────────────────────────────────────────────

    #[test]
    fn given_set_request_when_handled_then_returns_not_writable() {
        // Verifies: REQ-0032
        let req = SetRequest {
            request_id: RequestId::from(99),
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.1.0"),
                value: VarbindValue::Value(Value::Integer32(1)),
            }],
        };

        let resp = handle_set(&req);

        assert_eq!(resp.request_id, RequestId::from(99));
        assert_eq!(resp.error_status, ErrorStatus::NotWritable);
        assert_eq!(resp.error_index, 1);
    }

    // ── build_wire_trap ───────────────────────────────────────────────────────

    #[test]
    fn given_api_trap_pdu_when_built_then_prepends_sys_up_time_and_trap_oid() {
        // Verifies: REQ-0037, REQ-0038, REQ-0041, REQ-0046
        let api_pdu = TrapPdu {
            request_id: RequestId::from(5),
            trap_oid: oid("1.3.6.1.6.3.1.1.5.1"),
            varbinds: vec![Varbind {
                oid: oid("1.3.6.1.2.1.1.5.0"),
                value: VarbindValue::Value(Value::OctetString(b"host".to_vec())),
            }],
        };
        let start = Instant::now();

        let wire = build_wire_trap(&api_pdu, start);

        assert_eq!(wire.request_id, RequestId::from(5));
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

    // ── TrapPdu structure ─────────────────────────────────────────────────────

    #[test]
    fn trap_pdu_excludes_sys_up_time_field() {
        // Verifies: REQ-0039
        // TrapPdu must not include a sysUpTime.0 field. Constructing it via a
        // struct literal is compile-time enforcement: if sysUpTime were added as
        // a field, every struct literal would fail to compile (missing field),
        // making the omission intentional and always visible.
        let _pdu = TrapPdu {
            request_id: RequestId::from(1),
            trap_oid: oid("1.3.6.1.6.3.1.1.5.1"),
            varbinds: vec![],
        };
    }

    // ── build_wire_trap timing ────────────────────────────────────────────────

    #[test]
    fn given_known_construction_time_when_build_wire_trap_then_sys_up_time_reflects_elapsed() {
        // Verifies: REQ-0037
        let start = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
        let api_pdu = TrapPdu {
            request_id: RequestId::from(1),
            trap_oid: oid("1.3.6.1.6.3.1.1.5.1"),
            varbinds: vec![],
        };

        let wire = build_wire_trap(&api_pdu, start);

        // sysUpTime.0 is in hundredths of a second; 5 seconds ≈ 500 hundredths.
        let VarbindValue::Value(Value::TimeTicks(sys_up_time)) = &wire.varbinds[0].value else {
            panic!("expected TimeTicks for sysUpTime.0 varbind");
        };
        assert!(
            (500..=600).contains(sys_up_time),
            "expected sysUpTime near 500 hundredths of a second, got {sys_up_time}"
        );
    }

    // ── elapsed_hundredths ────────────────────────────────────────────────────

    #[test]
    fn given_start_time_just_now_when_elapsed_hundredths_then_returns_near_zero() {
        // Verifies: REQ-0037
        // A start time of Instant::now() has elapsed only nanoseconds, so the
        // result must be well below 5 hundredths.
        let start = Instant::now();

        let hundredths = elapsed_hundredths(start);

        assert!(hundredths < 5, "expected < 5, got {hundredths}");
    }

    #[test]
    fn given_start_time_one_second_ago_when_elapsed_hundredths_then_returns_around_100() {
        // Verifies: REQ-0037
        // 1 second = 100 hundredths; allow generous headroom for slow CI runners.
        let start = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();

        let hundredths = elapsed_hundredths(start);

        assert!(
            (100..=200).contains(&hundredths),
            "expected 100..=200, got {hundredths}"
        );
    }

    #[test]
    fn given_start_time_ten_seconds_ago_when_elapsed_hundredths_then_returns_around_1000() {
        // 10 seconds = 1000 hundredths; allow generous headroom for slow CI runners.
        let start = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();

        let hundredths = elapsed_hundredths(start);

        assert!(
            (1000..=1100).contains(&hundredths),
            "expected 1000..=1100, got {hundredths}"
        );
    }

    // ── handle_get_bulk size bounding (REQ-0133, REQ-0134) ────────────────────

    #[test]
    fn given_large_values_when_get_bulk_with_small_max_size_then_repeating_section_truncated() {
        // Verifies: REQ-0133, REQ-0134
        // A MIB with large OctetString values and a small max_response_size
        // must produce a truncated repeating section.
        let mut store = Store::new();
        for i in 0_u32..10 {
            store.set(
                oid(&format!("1.3.6.1.2.1.1.{i}.0")),
                Value::OctetString(vec![0xAA; 500]),
            );
        }
        let req = GetBulkRequest {
            request_id: RequestId::from(1),
            non_repeaters: 0,
            max_repetitions: 10,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };
        // With a 2000-byte limit, only a few 500-byte values should fit.
        // Budget: 2000 - 512 = 1488 bytes.
        // Each varbind: OID 1.3.6.1.2.1.1.x.0 has 9 arcs → content upper bound 45 bytes,
        // TLV = 1+1+45 = 47. Value: 500-byte OctetString → TLV = 1+2+500 = 503.
        // Inner = 47+503 = 550. Wrapping SEQUENCE = 1+2+550 = 553.
        // Row 1: 553 ≤ 1488 → accept (running=553).
        // Row 2: 553+553=1106 ≤ 1488 → accept (running=1106).
        // Row 3: 1106+553=1659 > 1488 → reject. 2 varbinds total.
        let resp = handle_get_bulk(&req, &store, 100, 2000);

        assert_eq!(resp.varbinds.len(), 2);
    }

    #[test]
    fn given_large_non_repeaters_when_get_bulk_with_small_max_size_then_non_repeaters_preserved() {
        // Verifies: REQ-0134
        // Non-repeating varbinds must not be truncated even when they are large.
        let mut store = Store::new();
        store.set(
            oid("1.3.6.1.2.1.1.1.0"),
            Value::OctetString(vec![0xBB; 1000]),
        );
        store.set(
            oid("1.3.6.1.2.1.1.2.0"),
            Value::OctetString(vec![0xCC; 1000]),
        );
        store.set(
            oid("1.3.6.1.2.1.1.3.0"),
            Value::OctetString(vec![0xDD; 1000]),
        );
        let req = GetBulkRequest {
            request_id: RequestId::from(2),
            non_repeaters: 2,
            max_repetitions: 10,
            varbinds: vec![
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.0.0"),
                    value: VarbindValue::Unspecified,
                },
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
        // Budget: 2000 - 512 = 1488 bytes.
        // Non-repeater #1: GETNEXT of 1.3.6.1.2.1.1.0.0 → 1.3.6.1.2.1.1.1.0 (9 arcs, 1000 bytes).
        //   OID TLV = 1+1+45 = 47. Value TLV = 1+2+1000 = 1003. Inner = 1050. Wrapping = 1+2+1050 = 1053.
        // Non-repeater #2: GETNEXT of 1.3.6.1.2.1.1.1.0 → 1.3.6.1.2.1.1.2.0 (9 arcs, 1000 bytes).
        //   Same estimate: 1053.
        // After non-repeaters: running = 2106.
        // Repeating column: GETNEXT of 1.3.6.1.2.1.1.2.0 → 1.3.6.1.2.1.1.3.0 (1000 bytes) → 1053.
        //   2106 + 1053 = 3159 > 1488 → row rejected.
        // Total: 2 non-repeater varbinds, 0 repeating varbinds.
        let resp = handle_get_bulk(&req, &store, 100, 2000);

        assert_eq!(resp.varbinds.len(), 2);
    }

    #[test]
    fn given_multiple_columns_when_size_exceeded_then_truncated_at_row_boundary() {
        // Verifies: REQ-0133, REQ-0134
        // With two repeating columns, truncation must occur at a complete row
        // boundary — the response must contain an even number of repeating varbinds.
        let mut store = Store::new();
        // Column A: 1.3.6.1.2.1.1.x.0
        // Column B: 1.3.6.1.2.1.2.x.0
        for i in 0_u32..20 {
            store.set(
                oid(&format!("1.3.6.1.2.1.1.{i}.0")),
                Value::OctetString(vec![0xAA; 200]),
            );
            store.set(
                oid(&format!("1.3.6.1.2.1.2.{i}.0")),
                Value::OctetString(vec![0xBB; 200]),
            );
        }
        let req = GetBulkRequest {
            request_id: RequestId::from(3),
            non_repeaters: 0,
            max_repetitions: 20,
            varbinds: vec![
                Varbind {
                    oid: oid("1.3.6.1.2.1.1"),
                    value: VarbindValue::Unspecified,
                },
                Varbind {
                    oid: oid("1.3.6.1.2.1.2"),
                    value: VarbindValue::Unspecified,
                },
            ],
        };
        // Budget: 3000 - 512 = 2488 bytes.
        // Each varbind: OID 1.3.6.1.2.1.x.y.0 has 9 arcs → content upper bound 45, TLV = 1+1+45 = 47.
        //   Value: 200-byte OctetString → TLV = 1+2+200 = 203. Inner = 47+203 = 250.
        //   Wrapping SEQUENCE = 1+2+250 = 253 (250 ≥ 128 so length_of_length = 2).
        // Row size (2 columns) = 253 + 253 = 506.
        // Row 1: 506 ≤ 2488 → accept (running=506).
        // Row 2: 1012 ≤ 2488 → accept.
        // Row 3: 1518 ≤ 2488 → accept.
        // Row 4: 2024 ≤ 2488 → accept.
        // Row 5: 2024+506=2530 > 2488 → reject.
        // 4 complete rows × 2 columns = 8 varbinds.
        let resp = handle_get_bulk(&req, &store, 100, 3000);

        assert_eq!(resp.varbinds.len(), 8);
    }

    #[test]
    fn given_zero_max_response_size_when_get_bulk_then_only_non_repeaters_returned() {
        // Verifies: REQ-0133
        // With max_response_size=0, varbind_budget = 0.saturating_sub(512) = 0, so
        // no repeating rows fit. Non-repeaters are added unconditionally before the
        // budget check, so the single non-repeater varbind must still appear.
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
        ]);
        let req = GetBulkRequest {
            request_id: RequestId::from(5),
            non_repeaters: 1,
            max_repetitions: 10,
            varbinds: vec![
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Unspecified,
                },
                Varbind {
                    oid: oid("1.3.0"),
                    value: VarbindValue::Unspecified,
                },
            ],
        };

        let resp = handle_get_bulk(&req, &store, 100, 0);

        // Only the non-repeater; the repeating section has budget 0 so no rows fit.
        assert_eq!(resp.varbinds.len(), 1);
        assert_eq!(resp.varbinds[0].oid, oid("1.3.6.1.2.1.1.2.0"));
    }

    #[test]
    fn given_estimated_varbind_size_is_always_at_least_actual_encoded_size() {
        // Verifies: REQ-0133
        // The estimator must never underestimate; doing so could cause the agent to
        // produce a response exceeding the negotiated message size limit.
        use crate::codec::ber::varbind::{encode_varbind, encode_varbind_value};

        let cases: &[(Varbind, &str)] = &[
            (
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Value(Value::Integer32(42)),
                },
                "Integer32",
            ),
            (
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Value(Value::OctetString(vec![0xAA; 200])),
                },
                "OctetString 200 bytes",
            ),
            (
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Value(Value::OctetString(vec![0xBB; 500])),
                },
                "OctetString 500 bytes",
            ),
            (
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::Value(Value::Counter64(u64::MAX)),
                },
                "Counter64",
            ),
            (
                Varbind {
                    oid: oid("1.3.6.1.2.1.1.1.0"),
                    value: VarbindValue::EndOfMibView,
                },
                "EndOfMibView",
            ),
        ];

        for (varbind, label) in cases {
            let estimate = estimated_varbind_wire_size(varbind);
            let encoded_value = encode_varbind_value(&varbind.value)
                .unwrap_or_else(|_| panic!("encode_varbind_value must succeed for {label}"));
            let actual_encoded = encode_varbind(&varbind.oid, &encoded_value);
            assert!(
                estimate >= actual_encoded.len(),
                "{label}: estimate {estimate} < actual encoded size {}",
                actual_encoded.len()
            );
        }
    }

    #[test]
    fn given_generous_max_response_size_when_get_bulk_then_all_repetitions_returned() {
        // Verifies: REQ-0133
        // With a generous max_response_size, all repetitions should be returned
        // as if the size limit did not exist.
        let store = store_with(&[
            ("1.3.6.1.2.1.1.1.0", Value::Integer32(1)),
            ("1.3.6.1.2.1.1.2.0", Value::Integer32(2)),
            ("1.3.6.1.2.1.1.3.0", Value::Integer32(3)),
        ]);
        let req = GetBulkRequest {
            request_id: RequestId::from(4),
            non_repeaters: 0,
            max_repetitions: 3,
            varbinds: vec![Varbind {
                oid: oid("1.3.0"),
                value: VarbindValue::Unspecified,
            }],
        };
        let resp = handle_get_bulk(&req, &store, 100, 0xFFFF);

        assert_eq!(resp.varbinds.len(), 3);
    }
}
