//! Newtypes for `SNMPv3` engine boots and engine time values.
//!
//! `EngineBoots` and `EngineTime` wrap the bare `u32` values that `SNMPv3`
//! uses for `snmpEngineBoots` and `snmpEngineTime` respectively.  Making
//! them distinct types prevents silent transposition at call sites such as
//! `is_in_time_window`, where a swap of the boots and time arguments would
//! otherwise be a security-relevant, compile-time-invisible bug.
//!
//! # Requirements
//! Implements: REQ-0094, REQ-0097, REQ-0098

/// The `snmpEngineBoots` counter — how many times the agent has initialised
/// since the engine ID was last set.
///
/// Wraps a `u32` and enforces the RFC 3414 §2.2 ceiling of `0x7FFF_FFFF`.
/// Once the counter reaches that value, authenticated communication is no
/// longer possible without reconfiguration.
///
/// # Requirements
/// Implements: REQ-0094, REQ-0097
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::engine_time::EngineBoots;
///
/// let boots = EngineBoots::from(3_u32);
/// assert_eq!(u32::from(boots), 3);
/// assert!(!boots.is_at_ceiling());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineBoots(u32);

impl EngineBoots {
    /// The RFC 3414 §2.2 ceiling value (`2^31 − 1 = 0x7FFF_FFFF`).
    ///
    /// Once `snmpEngineBoots` reaches this value the agent cannot perform
    /// authenticated communication without reconfiguration.
    ///
    /// # Requirements
    /// Implements: REQ-0097
    pub const CEILING: u32 = 0x7FFF_FFFF;

    /// A boots counter of zero.
    ///
    /// Used as the initial value for outbound traps, which send
    /// `snmpEngineBoots = 0` in the USM security parameters per RFC 3414.
    ///
    /// # Requirements
    /// Implements: REQ-0094
    pub const ZERO: Self = Self(0);

    /// Returns `true` when the counter has reached its RFC 3414 ceiling and
    /// can no longer be incremented.
    ///
    /// # Requirements
    /// Implements: REQ-0097
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::engine_time::EngineBoots;
    ///
    /// assert!(EngineBoots::from(EngineBoots::CEILING).is_at_ceiling());
    /// assert!(!EngineBoots::from(1_u32).is_at_ceiling());
    /// ```
    #[must_use]
    pub fn is_at_ceiling(self) -> bool {
        self.0 >= Self::CEILING
    }

    /// Return the next boots value, saturating at [`CEILING`][Self::CEILING]
    /// rather than wrapping.
    ///
    /// Callers that need to detect the ceiling before incrementing should
    /// check [`is_at_ceiling`][Self::is_at_ceiling] first.
    ///
    /// # Requirements
    /// Implements: REQ-0097
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::engine_time::EngineBoots;
    ///
    /// let boots = EngineBoots::from(5_u32);
    /// assert_eq!(u32::from(boots.saturating_increment()), 6);
    ///
    /// let ceiling = EngineBoots::from(EngineBoots::CEILING);
    /// assert_eq!(u32::from(ceiling.saturating_increment()), EngineBoots::CEILING);
    /// ```
    #[must_use]
    pub fn saturating_increment(self) -> Self {
        Self(self.0.min(Self::CEILING - 1) + 1)
    }
}

impl From<u32> for EngineBoots {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<EngineBoots> for u32 {
    fn from(boots: EngineBoots) -> Self {
        boots.0
    }
}

// ── EngineTime ────────────────────────────────────────────────────────────────

/// The `snmpEngineTime` value — seconds elapsed since the engine last
/// initialised (i.e. since `snmpEngineBoots` was last incremented).
///
/// Wraps a `u32` to make it a distinct type from [`EngineBoots`], preventing
/// accidental argument transposition at call sites that take both values.
///
/// # Requirements
/// Implements: REQ-0094, REQ-0098
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::engine_time::EngineTime;
///
/// let time = EngineTime::from(300_u32);
/// assert_eq!(u32::from(time), 300);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineTime(u32);

impl EngineTime {
    /// An engine time of zero seconds.
    ///
    /// # Requirements
    /// Implements: REQ-0094
    pub const ZERO: Self = Self(0);
}

impl From<u32> for EngineTime {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<EngineTime> for u32 {
    fn from(time: EngineTime) -> Self {
        time.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_value_below_ceiling_when_is_at_ceiling_then_false() {
        // Verifies: REQ-0097
        assert!(!EngineBoots::from(0_u32).is_at_ceiling());
        assert!(!EngineBoots::from(1_u32).is_at_ceiling());
        assert!(!EngineBoots::from(EngineBoots::CEILING - 1).is_at_ceiling());
    }

    #[test]
    fn given_value_at_ceiling_when_is_at_ceiling_then_true() {
        // Verifies: REQ-0097
        assert!(EngineBoots::from(EngineBoots::CEILING).is_at_ceiling());
    }

    #[test]
    fn given_value_above_ceiling_when_is_at_ceiling_then_true() {
        // Verifies: REQ-0097 — `>=` not `==`: values above the ceiling also report at-ceiling
        assert!(EngineBoots::from(u32::MAX).is_at_ceiling());
    }

    #[test]
    fn given_value_below_ceiling_when_saturating_increment_then_increments_by_one() {
        // Verifies: REQ-0097
        assert_eq!(
            u32::from(EngineBoots::from(0_u32).saturating_increment()),
            1
        );
        assert_eq!(
            u32::from(EngineBoots::from(5_u32).saturating_increment()),
            6
        );
        assert_eq!(
            u32::from(EngineBoots::from(EngineBoots::CEILING - 1).saturating_increment()),
            EngineBoots::CEILING
        );
    }

    #[test]
    fn given_value_at_ceiling_when_saturating_increment_then_stays_at_ceiling() {
        // Verifies: REQ-0097 — saturating_increment must not exceed the ceiling
        let ceiling = EngineBoots::from(EngineBoots::CEILING);
        assert_eq!(
            u32::from(ceiling.saturating_increment()),
            EngineBoots::CEILING
        );
    }

    #[test]
    fn given_value_above_ceiling_when_saturating_increment_then_stays_at_ceiling() {
        // Verifies: REQ-0097 — From<u32> accepts any u32; saturating_increment must
        // still cap at CEILING even when the stored value already exceeds it
        assert_eq!(
            u32::from(EngineBoots::from(u32::MAX).saturating_increment()),
            EngineBoots::CEILING
        );
    }

    #[test]
    fn given_engine_boots_when_round_tripped_through_u32_then_recovers_value() {
        // Verifies: REQ-0094
        let original: u32 = 42;
        let boots = EngineBoots::from(original);
        assert_eq!(u32::from(boots), original);
    }

    #[test]
    fn given_engine_time_when_round_tripped_through_u32_then_recovers_value() {
        // Verifies: REQ-0094
        let original: u32 = 300;
        let time = EngineTime::from(original);
        assert_eq!(u32::from(time), original);
    }

    #[test]
    fn given_two_engine_boots_when_compared_then_ordering_is_correct() {
        // Verifies: REQ-0094
        let lower = EngineBoots::from(1_u32);
        let higher = EngineBoots::from(2_u32);
        assert!(lower < higher);
        assert_eq!(lower, lower);
        assert_ne!(lower, higher);
    }

    #[test]
    fn given_two_engine_times_when_compared_then_ordering_is_correct() {
        // Verifies: REQ-0094
        let earlier = EngineTime::from(100_u32);
        let later = EngineTime::from(200_u32);
        assert!(earlier < later);
        assert_eq!(earlier, earlier);
        assert_ne!(earlier, later);
    }
}
