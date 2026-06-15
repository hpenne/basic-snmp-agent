//! Report PDU construction and OID statics for the dispatch validation pipeline.

use std::sync::LazyLock;

use crate::codec::Oid;
use log::{debug, trace};

use crate::usm::counters::UsmStatsCounter;

use super::{DispatchContext, DispatchInputs};

// Control-flow type for the validation pipeline — does not directly implement a requirement.
// Outcome of a failed security check: either send a Report PDU or silently discard.
//
// `Error` is intentionally not implemented: `Report` carries a valid encoded PDU to return to
// the manager (not an error description), and `Discard` signals a silent drop. Implementing
// `Error` would misrepresent these variants as error conditions.
pub(super) enum Reject {
    Report(Vec<u8>),
    Discard,
}

impl From<Reject> for Option<Vec<u8>> {
    fn from(reject: Reject) -> Self {
        match reject {
            Reject::Report(encoded_report) => Some(encoded_report),
            Reject::Discard => None,
        }
    }
}

/// Bit mask for the `reportableFlag` in `msgFlags` (RFC 3412 §7.1.3a).
pub(super) const REPORTABLE_FLAG: u8 = 0x04;

// Implements: REQ-0093, REQ-0104
pub(super) static UNKNOWN_ENGINE_IDS_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS
        .parse()
        .expect("USM_STATS_UNKNOWN_ENGINE_IDS is a valid OID constant")
});

// Implements: REQ-0078
pub(super) static UNKNOWN_USER_NAMES_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_UNKNOWN_USER_NAMES
        .parse()
        .expect("USM_STATS_UNKNOWN_USER_NAMES is a valid OID constant")
});

// Implements: REQ-0079
pub(super) static UNSUPPORTED_SEC_LEVELS_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS
        .parse()
        .expect("USM_STATS_UNSUPPORTED_SEC_LEVELS is a valid OID constant")
});

// Implements: REQ-0100
pub(super) static WRONG_DIGESTS_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_WRONG_DIGESTS
        .parse()
        .expect("USM_STATS_WRONG_DIGESTS is a valid OID constant")
});

// Implements: REQ-0098
pub(super) static NOT_IN_TIME_WINDOWS_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS
        .parse()
        .expect("USM_STATS_NOT_IN_TIME_WINDOWS is a valid OID constant")
});

// Implements: REQ-0101
pub(super) static DECRYPTION_ERRORS_OID: LazyLock<Oid> = LazyLock::new(|| {
    crate::usm::counters::USM_STATS_DECRYPTION_ERRORS
        .parse()
        .expect("USM_STATS_DECRYPTION_ERRORS is a valid OID constant")
});

/// OID for `snmpUnknownSecurityModels.0` (RFC 3412, SNMP-MPD-MIB).
// Implements: REQ-0115
pub(super) const SNMP_UNKNOWN_SECURITY_MODELS_OID: &str = "1.3.6.1.6.3.11.2.1.1.0";

// Implements: REQ-0115
pub(super) static UNKNOWN_SECURITY_MODELS_OID: LazyLock<Oid> = LazyLock::new(|| {
    SNMP_UNKNOWN_SECURITY_MODELS_OID
        .parse()
        .expect("SNMP_UNKNOWN_SECURITY_MODELS_OID is a valid OID constant")
});

/// Increment the counter selected by `select_counter`, and if `reportableFlag` is set in
/// `security_flags`, encode and return a `Reject::Report` carrying the encoded PDU;
/// otherwise return `Reject::Discard` (silent discard per RFC 3412 §7.1.3a).
pub(super) fn emit_report_response(
    ctx: &mut DispatchContext<'_>,
    select_counter: impl for<'a> FnOnce(&'a mut DispatchInputs<'_>) -> &'a mut UsmStatsCounter,
    counter_oid: &Oid,
    description: &str,
    msg_id: i32,
    security_flags: u8,
) -> Reject {
    // Scope the closure call so the mutable borrow of ctx.inputs ends before
    // we read engine_id, engine_boots, and engine_time below.
    let counter_value = {
        let counter = select_counter(&mut ctx.inputs);
        counter.saturating_increment();
        counter.get()
    };
    if security_flags & REPORTABLE_FLAG == 0 {
        trace!("{description} with reportableFlag unset, discarding silently");
        return Reject::Discard;
    }
    crate::codec::encode_v3_report(
        msg_id,
        ctx.inputs.engine_id,
        u32::from(ctx.inputs.engine_boots),
        u32::from(ctx.inputs.engine_time),
        counter_oid,
        counter_value,
    )
    .inspect_err(|encode_error| {
        debug!("failed to encode {description} report: {encode_error}");
    })
    .map_or(Reject::Discard, Reject::Report)
}
