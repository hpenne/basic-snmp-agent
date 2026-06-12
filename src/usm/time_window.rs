//! Time-window validation for USM authenticated messages.
//!
//! # Requirements
//! Implements: REQ-0098, REQ-0099

use crate::usm::engine_time::{EngineBoots, EngineTime};

/// Return `true` if an authenticated message's time parameters are within the
/// valid window, `false` otherwise.
///
/// Per RFC 3414 §3.2 step 7b, a message is within the time window when:
/// - `msg_boots` equals `engine_boots` (the boots counter must match exactly), **and**
/// - the absolute difference between `msg_time` and `engine_time` is ≤ 150 seconds.
///
/// A time-synchronisation probe sends `msg_boots = 0` and `msg_time = 0`
/// (REQ-0099). Because `engine_boots` is always ≥ 1 after initialisation,
/// the boots check always fails for such a probe, causing the agent to respond
/// with a Report PDU carrying the current `snmpEngineBoots` and `snmpEngineTime`.
///
/// Using [`EngineBoots`] and [`EngineTime`] as distinct types prevents silent
/// transposition of the boots and time arguments, which would be a
/// security-relevant bug in RFC 3414 replay-window validation.
///
/// # Requirements
/// Implements: REQ-0098, REQ-0099
#[must_use]
pub fn is_in_time_window(
    msg_boots: EngineBoots,
    msg_time: EngineTime,
    engine_boots: EngineBoots,
    engine_time: EngineTime,
) -> bool {
    if msg_boots != engine_boots {
        return false;
    }
    // Widen to i64 before subtraction to avoid u32 wrapping.
    let msg_time_u32 = u32::from(msg_time);
    let engine_time_u32 = u32::from(engine_time);
    let time_diff = (i64::from(msg_time_u32) - i64::from(engine_time_u32)).unsigned_abs();
    time_diff <= 150
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_boots(v: u32) -> EngineBoots {
        EngineBoots::from(v)
    }

    fn engine_time(v: u32) -> EngineTime {
        EngineTime::from(v)
    }

    #[test]
    fn given_matching_boots_and_same_time_when_check_then_in_window() {
        // Verifies: REQ-0098
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(1000)
        ));
    }

    #[test]
    fn given_matching_boots_and_time_within_150s_when_check_then_in_window() {
        // Verifies: REQ-0098
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(900)
        ));
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(900),
            engine_boots(5),
            engine_time(1000)
        ));
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1100),
            engine_boots(5),
            engine_time(1000)
        ));
    }

    #[test]
    fn given_matching_boots_and_time_at_boundary_150s_when_check_then_in_window() {
        // Verifies: REQ-0098 — boundary is inclusive
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(850),
            engine_boots(5),
            engine_time(1000)
        )); // exactly 150 behind
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(850)
        )); // same, reversed
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1150),
            engine_boots(5),
            engine_time(1000)
        )); // exactly 150 ahead
        assert!(is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(1150)
        )); // same, reversed
    }

    #[test]
    fn given_matching_boots_and_time_outside_150s_when_check_then_not_in_window() {
        // Verifies: REQ-0098
        assert!(!is_in_time_window(
            engine_boots(5),
            engine_time(849),
            engine_boots(5),
            engine_time(1000)
        ));
        assert!(!is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(849)
        ));
        assert!(!is_in_time_window(
            engine_boots(5),
            engine_time(1151),
            engine_boots(5),
            engine_time(1000)
        ));
        assert!(!is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(5),
            engine_time(1151)
        ));
    }

    #[test]
    fn given_boots_mismatch_when_check_then_not_in_window() {
        // Verifies: REQ-0098
        assert!(!is_in_time_window(
            engine_boots(5),
            engine_time(1000),
            engine_boots(6),
            engine_time(1000)
        ));
        assert!(!is_in_time_window(
            engine_boots(6),
            engine_time(1000),
            engine_boots(5),
            engine_time(1000)
        ));
        assert!(!is_in_time_window(
            engine_boots(0),
            engine_time(1000),
            engine_boots(1),
            engine_time(1000)
        ));
    }

    #[test]
    fn given_time_sync_probe_boots_zero_when_check_then_not_in_window() {
        // Verifies: REQ-0099 — boots=0 always fails since engine_boots >= 1
        assert!(!is_in_time_window(
            engine_boots(0),
            engine_time(0),
            engine_boots(1),
            engine_time(0)
        ));
        assert!(!is_in_time_window(
            engine_boots(0),
            engine_time(0),
            engine_boots(3),
            engine_time(500)
        ));
    }

    #[test]
    fn given_both_boots_zero_when_in_time_window_then_returns_true() {
        // Verifies: REQ-0098 — documents behavior when engine_boots == 0 (misconfiguration or
        // fresh state before initialisation). The function does not guard against this; callers
        // must ensure engine_boots >= 1 per RFC 3414 §2.2.
        assert!(is_in_time_window(
            engine_boots(0),
            engine_time(0),
            engine_boots(0),
            engine_time(0)
        ));
    }
}
