//! SNMP Object Identifier type and parsing.

use std::fmt;
use std::str::FromStr;

/// An SNMP Object Identifier represented as a sequence of unsigned 32-bit components.
///
/// OIDs are compared lexicographically, component by component, with shorter prefixes
/// sorting before longer ones (e.g. `1.3.6` < `1.3.6.1`).
///
/// # Structural rules
///
/// A valid OID must satisfy all of the following:
///
/// - It must have at least two components.
/// - The first component must be `0`, `1`, or `2`.
/// - If the first component is `0` or `1`, the second component must be `≤ 39`.
/// - If the first component is `2`, there is no upper bound on the second component
///   beyond the `u32::MAX` cap.  BER encodes the combined first-two-arc value
///   (`40 * first + second`) as a base-128 variable-length integer (X.690 §8.19.4),
///   so large second arcs like `2.999` (used in X.660 examples) are perfectly valid.
///
/// The infallible constructor [`Oid::from_slice`] enforces these rules with `assert!`
/// panics.  [`TryFrom<Vec<u32>>`] and [`FromStr`] return a [`ParseOidError`] instead.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::Oid;
///
/// let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
/// assert_eq!(oid.to_string(), "1.3.6.1.2.1");
///
/// let oid2 = Oid::try_from(vec![2u32, 999]).unwrap();
/// assert_eq!(oid2.to_string(), "2.999");
/// ```
// `Vec<u32>` compares lexicographically, component by component, which matches
// the ASN.1/SNMP OID ordering defined in RFC 2578 §3.1. The derived `Ord` is
// therefore correct and intentional.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(Vec<u32>);

impl Oid {
    /// Creates an `Oid` from a slice of component values.
    ///
    /// # Panics
    ///
    /// Panics if the components violate the OID structural rules:
    ///
    /// - The slice must have at least two elements.
    /// - The first element must be `0`, `1`, or `2`.
    /// - If the first element is `0` or `1`, the second element must be `≤ 39`.
    /// - If the first element is `2`, any `u32` value is accepted for the second
    ///   element (e.g. `[2, 999]` is valid).
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::codec::Oid;
    ///
    /// let oid = Oid::from_slice(&[1, 3, 6, 1]);
    /// assert_eq!(oid.to_string(), "1.3.6.1");
    ///
    /// let oid2 = Oid::from_slice(&[2, 999]);
    /// assert_eq!(oid2.to_string(), "2.999");
    /// ```
    #[must_use]
    pub fn from_slice(components: &[u32]) -> Self {
        if let Err(kind) = validate_oid_components(components) {
            panic!("{}", ParseOidError { kind });
        }
        Self(components.to_vec())
    }

    /// Returns the OID components as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<Vec<u32>> for Oid {
    type Error = ParseOidError;

    /// Attempts to create an `Oid` from a vector of component values, returning
    /// a [`ParseOidError`] on failure rather than panicking.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseOidError`] if the components violate the OID structural
    /// rules:
    ///
    /// - fewer than two components
    /// - first arc > 2
    /// - second arc > 39 when first arc is 0 or 1
    ///
    /// When first arc is 2, any `u32` value is accepted for the second arc.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::codec::Oid;
    ///
    /// assert!(Oid::try_from(vec![1u32, 3, 6, 1]).is_ok());
    /// assert!(Oid::try_from(vec![2u32, 999]).is_ok());
    /// assert!(Oid::try_from(vec![0u32, 40]).is_err());
    /// ```
    fn try_from(components: Vec<u32>) -> Result<Self, Self::Error> {
        validate_oid_components(&components).map_err(|kind| ParseOidError { kind })?;
        Ok(Self(components))
    }
}

impl FromStr for Oid {
    type Err = ParseOidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseOidError {
                kind: OidErrorKind::EmptyString,
            });
        }
        // Leading and trailing dot checks are intentionally ordered before the
        // consecutive-dot check.  This means ".." is reported as "leading dot"
        // (the first thing wrong with it) rather than "consecutive dots", and
        // "1.." is reported as "trailing dot" rather than "consecutive dots".
        // Each input is described by its first detected problem.
        if s.starts_with('.') {
            return Err(ParseOidError {
                kind: OidErrorKind::LeadingDot,
            });
        }
        if s.ends_with('.') {
            return Err(ParseOidError {
                kind: OidErrorKind::TrailingDot,
            });
        }
        if s.contains("..") {
            return Err(ParseOidError {
                kind: OidErrorKind::ConsecutiveDots,
            });
        }

        let components = s
            .split('.')
            .map(|part| {
                // Parse first so that non-numeric input (e.g. "0 ") is caught as
                // InvalidComponent before the leading-zero check ever runs.
                let value = part.parse::<u32>().map_err(|source| ParseOidError {
                    kind: OidErrorKind::InvalidComponent {
                        part: part.to_string(),
                        source,
                    },
                })?;
                // Reject leading zeros (e.g. "06") as ambiguous; this matches
                // the behaviour of OpenSSL and Net-SNMP.  A bare "0" is fine.
                if part.len() > 1 && part.starts_with('0') {
                    return Err(ParseOidError {
                        kind: OidErrorKind::LeadingZero {
                            part: part.to_string(),
                        },
                    });
                }
                Ok(value)
            })
            .collect::<Result<Vec<u32>, _>>()?;

        validate_oid_components(&components).map_err(|kind| ParseOidError { kind })?;

        Ok(Self(components))
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter();
        // The construction invariant guarantees at least two components, so
        // `iter.next()` will never actually return `None`.  The guard is kept
        // for defensive completeness in case the invariant is ever weakened.
        if let Some(first) = iter.next() {
            write!(f, "{first}")?;
            for component in iter {
                write!(f, ".{component}")?;
            }
        }
        Ok(())
    }
}

/// Error returned when parsing a dotted-decimal OID string fails.
#[derive(Debug)]
pub struct ParseOidError {
    kind: OidErrorKind,
}

impl ParseOidError {
    /// Returns the [`OidErrorCategory`] for this error, allowing callers to
    /// distinguish error kinds programmatically without string matching.
    #[must_use]
    pub fn category(&self) -> OidErrorCategory {
        match &self.kind {
            OidErrorKind::EmptyString => OidErrorCategory::EmptyString,
            OidErrorKind::LeadingDot => OidErrorCategory::LeadingDot,
            OidErrorKind::TrailingDot => OidErrorCategory::TrailingDot,
            OidErrorKind::ConsecutiveDots => OidErrorCategory::ConsecutiveDots,
            OidErrorKind::LeadingZero { .. } => OidErrorCategory::LeadingZero,
            OidErrorKind::TooFewComponents(_) => OidErrorCategory::TooFewComponents,
            OidErrorKind::InvalidFirstArc(_) => OidErrorCategory::InvalidFirstArc,
            OidErrorKind::InvalidSecondArc { .. } => OidErrorCategory::InvalidSecondArc,
            OidErrorKind::InvalidComponent { .. } => OidErrorCategory::InvalidComponent,
        }
    }
}

impl fmt::Display for ParseOidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

// Delegate to OidErrorKind::source() to avoid duplicating the match logic.
impl std::error::Error for ParseOidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

/// A fieldless mirror of [`OidErrorKind`] that callers can match on without
/// inspecting error message strings.
///
/// Obtain a value via [`ParseOidError::category`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OidErrorCategory {
    /// The input string was empty.
    EmptyString,
    /// The input string started with a dot.
    LeadingDot,
    /// The input string ended with a dot.
    TrailingDot,
    /// The input string contained two consecutive dots (`..`).
    ConsecutiveDots,
    /// A component had a leading zero (e.g. `"06"`).
    LeadingZero,
    /// The OID had fewer than two components.
    TooFewComponents,
    /// The first arc was not `0`, `1`, or `2`.
    InvalidFirstArc,
    /// The second arc was `> 39` when the first arc was `0` or `1`.
    InvalidSecondArc,
    /// A component could not be parsed as a `u32`.
    InvalidComponent,
}

/// Structured error kind for OID validation failures.
#[derive(Debug)]
enum OidErrorKind {
    EmptyString,
    LeadingDot,
    TrailingDot,
    ConsecutiveDots,
    LeadingZero {
        part: String,
    },
    TooFewComponents(usize),
    InvalidFirstArc(u32),
    InvalidSecondArc {
        first: u32,
        second: u32,
    },
    InvalidComponent {
        part: String,
        source: std::num::ParseIntError,
    },
}

impl fmt::Display for OidErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyString => write!(f, "invalid OID: empty string"),
            Self::LeadingDot => write!(f, "invalid OID: leading dot"),
            Self::TrailingDot => write!(f, "invalid OID: trailing dot"),
            Self::ConsecutiveDots => write!(f, "invalid OID: consecutive dots"),
            Self::LeadingZero { part } => {
                write!(f, "invalid OID: component {part:?} has a leading zero")
            }
            Self::TooFewComponents(n) => write!(
                f,
                "invalid OID: an OID must have at least two components, got {n}"
            ),
            Self::InvalidFirstArc(v) => write!(
                f,
                "invalid OID: first OID component must be 0, 1, or 2, got {v}"
            ),
            Self::InvalidSecondArc { first, second } => write!(
                f,
                "invalid OID: second OID component must be ≤ 39 when first is {first}, got {second}"
            ),
            Self::InvalidComponent { part, source } => {
                write!(f, "invalid OID: invalid component {part:?}: {source}")
            }
        }
    }
}

// Expose the wrapped ParseIntError via source() so that error chain
// walkers can inspect the root cause without parsing the Display output.
impl std::error::Error for OidErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidComponent { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Validates OID structural rules, returning an `OidErrorKind` on violation.
fn validate_oid_components(components: &[u32]) -> Result<(), OidErrorKind> {
    if components.len() < 2 {
        return Err(OidErrorKind::TooFewComponents(components.len()));
    }
    let first = components[0];
    let second = components[1];
    if first > 2 {
        return Err(OidErrorKind::InvalidFirstArc(first));
    }
    // When first is 0 or 1, the second arc must be <= 39 (X.660).
    // When first is 2, BER encodes the combined value 40*first+second as a
    // base-128 variable-length integer (X.690 §8.19.4), so there is no
    // single-byte limit; any u32 value is valid.
    if first <= 1 && second > 39 {
        return Err(OidErrorKind::InvalidSecondArc { first, second });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Oid construction ---

    #[test]
    fn oid_from_slice() {
        let oid = Oid::from_slice(&[1, 3, 6, 1]);
        assert_eq!(oid.as_slice(), &[1, 3, 6, 1]);
    }

    #[test]
    fn oid_try_from_vec() {
        let oid = Oid::try_from(vec![1u32, 3, 6, 1, 2, 1]).unwrap();
        assert_eq!(oid.as_slice(), &[1, 3, 6, 1, 2, 1]);
    }

    #[test]
    #[should_panic(expected = "at least two components")]
    fn oid_from_slice_panics_on_empty() {
        let _ = Oid::from_slice(&[]);
    }

    #[test]
    #[should_panic(expected = "at least two components")]
    fn oid_from_slice_panics_on_single_component() {
        let _ = Oid::from_slice(&[1]);
    }

    #[test]
    #[should_panic(expected = "first OID component must be 0, 1, or 2")]
    fn oid_from_slice_panics_on_invalid_first_component() {
        let _ = Oid::from_slice(&[3, 0]);
    }

    #[test]
    #[should_panic(expected = "second OID component must be")]
    fn oid_from_slice_panics_on_second_component_too_large() {
        let _ = Oid::from_slice(&[0, 40]);
    }

    #[test]
    fn oid_try_from_vec_panics_on_empty() {
        assert!(Oid::try_from(vec![]).is_err());
    }

    // When first arc is 2, any u32 second arc is valid (BER uses base-128
    // variable-length encoding for the combined 40*first+second value).
    #[test]
    fn oid_from_slice_arc2_second_arc_boundary() {
        // 40, 175, 176, and 999 are all valid when first is 2.
        let oid40 = Oid::from_slice(&[2, 40]);
        assert_eq!(oid40.as_slice(), &[2, 40]);
        let oid175 = Oid::from_slice(&[2, 175]);
        assert_eq!(oid175.as_slice(), &[2, 175]);
        let oid176 = Oid::from_slice(&[2, 176]);
        assert_eq!(oid176.as_slice(), &[2, 176]);
        let oid999 = Oid::from_slice(&[2, 999]);
        assert_eq!(oid999.as_slice(), &[2, 999]);
    }

    // --- TryFrom<Vec<u32>> ---

    #[test]
    fn oid_try_from_vec_success() {
        let oid = Oid::try_from(vec![1u32, 3, 6, 1]).unwrap();
        assert_eq!(oid.as_slice(), &[1, 3, 6, 1]);
    }

    #[test]
    fn oid_try_from_vec_failure_second_too_large() {
        let oid_error = Oid::try_from(vec![0u32, 40]).unwrap_err();
        assert!(
            oid_error.to_string().contains("second OID component"),
            "unexpected error: {oid_error}"
        );
    }

    // --- Oid::Display ---

    #[test]
    fn oid_display_dotted_decimal() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1]);
        assert_eq!(oid.to_string(), "1.3.6.1.2.1");
    }

    // --- Oid::FromStr ---

    #[test]
    fn oid_parse_round_trip() {
        let input = "1.3.6.1.2.1";
        let oid: Oid = input.parse().unwrap();
        assert_eq!(oid.to_string(), input);
    }

    #[test]
    fn oid_parse_error_single_component() {
        let parse_error = "42".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("at least two components"),
            "unexpected error: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_error_empty_string() {
        let parse_error = "".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.to_string(), "invalid OID: empty string");
    }

    #[test]
    fn oid_parse_error_invalid_component() {
        let parse_error = "1.3.foo.1".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("invalid component"),
            "unexpected error: {parse_error}"
        );
        // The source error text must also appear in Display.
        assert!(
            parse_error
                .to_string()
                .contains("invalid digit found in string"),
            "expected chained source in Display, got: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_error_negative_component() {
        // Negative numbers are not valid OID components (u32 parse rejects them).
        let parse_error = "1.3.-1".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("invalid component"),
            "unexpected error: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_error_invalid_first_component() {
        let parse_error = "3.0".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("first OID component"),
            "unexpected error: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_error_second_component_too_large() {
        let parse_error = "0.40".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("second OID component"),
            "unexpected error: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_arc2_large_second_arc_accepted() {
        // 2.176 and 2.999 are valid OIDs; the 175 limit was wrong.
        assert!("2.176".parse::<Oid>().is_ok());
        assert!("2.999".parse::<Oid>().is_ok());
    }

    #[test]
    fn oid_parse_error_leading_dot() {
        let parse_error = ".1.3.6".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.to_string(), "invalid OID: leading dot");
    }

    #[test]
    fn oid_parse_error_trailing_dot() {
        let parse_error = "1.3.6.".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.to_string(), "invalid OID: trailing dot");
    }

    #[test]
    fn oid_parse_error_consecutive_dots() {
        let parse_error = "1..3.6.1".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.to_string().contains("consecutive dots"),
            "unexpected error: {parse_error}"
        );
    }

    // ".." starts with a dot, so it is reported as "leading dot" (the first
    // detected problem), not "consecutive dots".
    #[test]
    fn oid_parse_double_dot_only_reports_leading_dot() {
        let parse_error = "..".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::LeadingDot);
        assert_eq!(parse_error.to_string(), "invalid OID: leading dot");
    }

    // "1.." ends with a dot, so it is reported as "trailing dot", not
    // "consecutive dots".
    #[test]
    fn oid_parse_trailing_double_dot_reports_trailing_dot() {
        let parse_error = "1..".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::TrailingDot);
        assert_eq!(parse_error.to_string(), "invalid OID: trailing dot");
    }

    // --- Leading zero tests ---

    #[test]
    fn oid_parse_error_leading_zero_in_component() {
        let parse_error = "1.3.06.1".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::LeadingZero);
        assert!(
            parse_error.to_string().contains("leading zero"),
            "unexpected error: {parse_error}"
        );
        assert!(
            parse_error.to_string().contains("\"06\""),
            "expected component name in error, got: {parse_error}"
        );
    }

    #[test]
    fn oid_parse_zero_components_are_valid() {
        // "1.0.0" has bare zero components, which are legitimate.
        assert!("1.0.0".parse::<Oid>().is_ok());
    }

    // --- Leading-zero vs. invalid-component priority ---

    #[test]
    fn oid_parse_zero_followed_by_space_reports_invalid_component_not_leading_zero() {
        let parse_error = "1.3.0 .1".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::InvalidComponent);
        assert!(
            parse_error.to_string().contains("\"0 \""),
            "expected offending component in error, got: {parse_error}"
        );
    }

    // --- OidErrorCategory tests ---

    #[test]
    fn oid_error_category_empty_string() {
        let parse_error = "".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::EmptyString);
    }

    #[test]
    fn oid_error_category_invalid_component() {
        let parse_error = "1.3.foo.1".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::InvalidComponent);
    }

    #[test]
    fn oid_error_category_too_few_components() {
        let parse_error = "42".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::TooFewComponents);
    }

    #[test]
    fn oid_error_category_invalid_first_arc() {
        let parse_error = "3.0".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::InvalidFirstArc);
    }

    #[test]
    fn oid_error_category_invalid_second_arc() {
        let parse_error = "0.40".parse::<Oid>().unwrap_err();
        assert_eq!(parse_error.category(), OidErrorCategory::InvalidSecondArc);
    }

    // --- Oid::Ord ---

    #[test]
    fn oid_ord_different_last_component() {
        let a: Oid = "1.3.6".parse().unwrap();
        let b: Oid = "1.3.7".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn oid_ord_prefix_less_than_longer() {
        let shorter: Oid = "1.3.6".parse().unwrap();
        let longer: Oid = "1.3.6.1".parse().unwrap();
        assert!(shorter < longer);
    }

    #[test]
    fn oid_ord_equal() {
        let a: Oid = "1.3.6.1".parse().unwrap();
        let b: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn oid_ord_first_component_differs() {
        let a: Oid = "1.3.6".parse().unwrap();
        let b: Oid = "2.0.0".parse().unwrap();
        assert!(a < b);
    }

    // --- ParseOidError ---

    #[test]
    fn parse_oid_error_implements_error_trait() {
        let parse_error = "".parse::<Oid>().unwrap_err();
        // Verify the trait bound is satisfied by using it as &dyn Error.
        let _: &dyn std::error::Error = &parse_error;
    }

    #[test]
    fn parse_oid_error_source_is_some_for_invalid_component() {
        use std::error::Error;
        let parse_error = "1.3.foo".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.source().is_some(),
            "expected a chained source error for an invalid component"
        );
    }

    #[test]
    fn parse_oid_error_source_is_none_for_empty_string() {
        use std::error::Error;
        let parse_error = "".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.source().is_none(),
            "expected no chained source error for an empty string"
        );
    }

    #[test]
    fn parse_oid_error_source_is_none_for_structural_violation() {
        use std::error::Error;
        let parse_error = "3.0".parse::<Oid>().unwrap_err();
        assert!(
            parse_error.source().is_none(),
            "expected no chained source error for a structural violation"
        );
    }

    #[test]
    fn given_first_arc_0_second_arc_39_when_parsed_then_succeeds() {
        // Verifies: REQ-0055 (OID structural rules from RFC 3411/X.660)
        // 39 is the maximum valid second arc when first is 0. The mutant
        // `> with >=` in validate_oid_components would incorrectly reject it.
        let oid = "0.39.1".parse::<Oid>().unwrap();
        assert_eq!(oid.as_slice(), &[0, 39, 1]);
    }

    #[test]
    fn given_first_arc_1_second_arc_39_when_parsed_then_succeeds() {
        // Verifies: REQ-0055 (OID structural rules from RFC 3411/X.660)
        // 39 is the maximum valid second arc when first is 1. The mutant
        // `> with >=` in validate_oid_components would incorrectly reject it.
        let oid = "1.39.1".parse::<Oid>().unwrap();
        assert_eq!(oid.as_slice(), &[1, 39, 1]);
    }
}
