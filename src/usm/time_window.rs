//! Time-window validation for USM authenticated messages.
//!
//! # Requirements
//! Implements: REQ-0098, REQ-0099

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
/// # Requirements
/// Implements: REQ-0098, REQ-0099
#[must_use]
pub fn is_in_time_window(
    msg_boots: u32,
    msg_time: u32,
    engine_boots: u32,
    engine_time: u32,
) -> bool {
    if msg_boots != engine_boots {
        return false;
    }
    // Widen to i64 before subtraction to avoid u32 wrapping.
    let time_diff = (i64::from(msg_time) - i64::from(engine_time)).unsigned_abs();
    time_diff <= 150
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_matching_boots_and_same_time_when_check_then_in_window() {
        // Verifies: REQ-0098
        assert!(is_in_time_window(5, 1000, 5, 1000));
    }

    #[test]
    fn given_matching_boots_and_time_within_150s_when_check_then_in_window() {
        // Verifies: REQ-0098
        assert!(is_in_time_window(5, 1000, 5, 900));
        assert!(is_in_time_window(5, 900, 5, 1000));
        assert!(is_in_time_window(5, 1100, 5, 1000));
    }

    #[test]
    fn given_matching_boots_and_time_at_boundary_150s_when_check_then_in_window() {
        // Verifies: REQ-0098 — boundary is inclusive
        assert!(is_in_time_window(5, 850, 5, 1000)); // exactly 150 behind
        assert!(is_in_time_window(5, 1000, 5, 850)); // same, reversed
        assert!(is_in_time_window(5, 1150, 5, 1000)); // exactly 150 ahead
        assert!(is_in_time_window(5, 1000, 5, 1150)); // same, reversed
    }

    #[test]
    fn given_matching_boots_and_time_outside_150s_when_check_then_not_in_window() {
        // Verifies: REQ-0098
        assert!(!is_in_time_window(5, 849, 5, 1000));
        assert!(!is_in_time_window(5, 1000, 5, 849));
        assert!(!is_in_time_window(5, 1151, 5, 1000));
        assert!(!is_in_time_window(5, 1000, 5, 1151));
    }

    #[test]
    fn given_boots_mismatch_when_check_then_not_in_window() {
        // Verifies: REQ-0098
        assert!(!is_in_time_window(5, 1000, 6, 1000));
        assert!(!is_in_time_window(6, 1000, 5, 1000));
        assert!(!is_in_time_window(0, 1000, 1, 1000));
    }

    #[test]
    fn given_time_sync_probe_boots_zero_when_check_then_not_in_window() {
        // Verifies: REQ-0099 — boots=0 always fails since engine_boots >= 1
        assert!(!is_in_time_window(0, 0, 1, 0));
        assert!(!is_in_time_window(0, 0, 3, 500));
    }

    #[test]
    fn given_both_boots_zero_when_in_time_window_then_returns_true() {
        // Verifies: REQ-0098 — documents behavior when engine_boots == 0 (misconfiguration or
        // fresh state before initialisation). The function does not guard against this; callers
        // must ensure engine_boots >= 1 per RFC 3414 §2.2.
        assert!(is_in_time_window(0, 0, 0, 0));
    }
}
