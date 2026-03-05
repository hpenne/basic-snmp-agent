//! ASN.1/BER codec primitives for SNMP.
//!
//! This crate currently provides:
//!
//! - [`Oid`]: an SNMP Object Identifier represented as a sequence of unsigned
//!   32-bit components, with dotted-decimal [`Display`](std::fmt::Display) and
//!   [`FromStr`](std::str::FromStr) implementations.
//! - [`ParseOidError`]: the error type returned when a dotted-decimal OID
//!   string cannot be parsed, including an optional chained source error.
//! - [`Value`]: an `SMIv2` value carried in an SNMP varbind, covering all nine
//!   standard `SMIv2` types defined in RFC 2578.

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
/// use codec::Oid;
///
/// let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
/// assert_eq!(oid.to_string(), "1.3.6.1.2.1");
///
/// let oid2 = Oid::try_from(vec![2u32, 999]).unwrap();
/// assert_eq!(oid2.to_string(), "2.999");
/// ```
// `Vec<u32>` compares lexicographically, component by component, which matches
// the ASN.1/SNMP OID ordering defined in RFC 2578 §3.1.  The derived `Ord` is
// therefore correct and intentional.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(Vec<u32>);

/// Structured error kind for OID validation failures.
#[derive(Debug)]
enum OidErrorKind {
    EmptyString,
    LeadingDot,
    TrailingDot,
    ConsecutiveDots,
    LeadingZero { part: String },
    TooFewComponents(usize),
    InvalidFirstArc(u32),
    InvalidSecondArc { first: u32, second: u32 },
    InvalidComponent { part: String, source: std::num::ParseIntError },
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
    /// use codec::Oid;
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
    /// use codec::Oid;
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

impl fmt::Display for ParseOidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            OidErrorKind::EmptyString => write!(f, "invalid OID: empty string"),
            OidErrorKind::LeadingDot => write!(f, "invalid OID: leading dot"),
            OidErrorKind::TrailingDot => write!(f, "invalid OID: trailing dot"),
            OidErrorKind::ConsecutiveDots => write!(f, "invalid OID: consecutive dots"),
            OidErrorKind::LeadingZero { part } => write!(
                f,
                "invalid OID: component {part:?} has a leading zero"
            ),
            OidErrorKind::TooFewComponents(n) => write!(
                f,
                "invalid OID: an OID must have at least two components, got {n}"
            ),
            OidErrorKind::InvalidFirstArc(v) => write!(
                f,
                "invalid OID: first OID component must be 0, 1, or 2, got {v}"
            ),
            OidErrorKind::InvalidSecondArc { first, second } => write!(
                f,
                "invalid OID: second OID component must be \u{2264} 39 when first is {first}, got {second}"
            ),
            OidErrorKind::InvalidComponent { part, source } => {
                write!(f, "invalid OID: invalid component {part:?}: {source}")
            }
        }
    }
}

impl std::error::Error for ParseOidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let OidErrorKind::InvalidComponent { source, .. } = &self.kind {
            Some(source)
        } else {
            None
        }
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

impl FromStr for Oid {
    type Err = ParseOidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseOidError { kind: OidErrorKind::EmptyString });
        }
        // Leading and trailing dot checks are intentionally ordered before the
        // consecutive-dot check.  This means ".." is reported as "leading dot"
        // (the first thing wrong with it) rather than "consecutive dots", and
        // "1.." is reported as "trailing dot" rather than "consecutive dots".
        // Each input is described by its first detected problem.
        if s.starts_with('.') {
            return Err(ParseOidError { kind: OidErrorKind::LeadingDot });
        }
        if s.ends_with('.') {
            return Err(ParseOidError { kind: OidErrorKind::TrailingDot });
        }
        if s.contains("..") {
            return Err(ParseOidError { kind: OidErrorKind::ConsecutiveDots });
        }

        let components = s
            .split('.')
            .map(|part| {
                // Reject leading zeros (e.g. "06") as ambiguous; this matches
                // the behaviour of OpenSSL and Net-SNMP.  A bare "0" is fine.
                if part.len() > 1 && part.starts_with('0') {
                    return Err(ParseOidError {
                        kind: OidErrorKind::LeadingZero { part: part.to_string() },
                    });
                }
                part.parse::<u32>().map_err(|source| ParseOidError {
                    kind: OidErrorKind::InvalidComponent {
                        part: part.to_string(),
                        source,
                    },
                })
            })
            .collect::<Result<Vec<u32>, _>>()?;

        validate_oid_components(&components)
            .map_err(|kind| ParseOidError { kind })?;

        Ok(Self(components))
    }
}

/// Formats a byte slice as an uppercase hex string without separators.
///
/// Used internally by [`Value::OctetString`] and [`Value::Opaque`] Display impls.
/// An empty slice intentionally produces an empty string, consistent with
/// zero-length SNMP OCTET STRING values.
fn fmt_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02X}")?;
    }
    Ok(())
}

/// An `SMIv2` value carried in an SNMP varbind.
///
/// Covers all nine standard `SMIv2` types defined in RFC 2578.
///
/// # Examples
///
/// ```
/// use codec::{Oid, Value};
///
/// let v = Value::Integer32(-1);
/// let ip = Value::IpAddress([192, 168, 1, 1]);
/// let oid: Oid = "1.3.6.1".parse().unwrap();
/// let o = Value::ObjectIdentifier(oid);
/// let s = Value::OctetString(b"hello".to_vec());
/// let c = Value::Counter32(u32::MAX);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// A signed 32-bit integer (`SNMPv2` `Integer`).
    Integer32(i32),
    /// An SNMP Object Identifier.
    ObjectIdentifier(Oid),
    /// An IPv4 address as four octets in network order.
    IpAddress([u8; 4]),
    /// An arbitrary byte string (`OCTET STRING`).
    OctetString(Vec<u8>),
    /// An unsigned 32-bit monotonically increasing counter that wraps at `u32::MAX`.
    Counter32(u32),
    /// An unsigned 64-bit monotonically increasing counter that wraps at `u64::MAX`.
    Counter64(u64),
    /// An unsigned 32-bit gauge that may increase or decrease, latching at `u32::MAX`.
    Gauge32(u32),
    /// Time in hundredths of a second since some epoch.
    TimeTicks(u32),
    /// Opaque arbitrary ASN.1 data encoded as a byte string.
    Opaque(Vec<u8>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer32(n) => write!(f, "{n}"),
            Value::ObjectIdentifier(oid) => write!(f, "{oid}"),
            // Display as dotted-decimal, consistent with conventional IPv4 notation.
            Value::IpAddress(octets) => {
                write!(f, "{}", std::net::Ipv4Addr::from(*octets))
            }
            // Both display as raw hex; use Debug to distinguish the variant.
            Value::OctetString(bytes) | Value::Opaque(bytes) => fmt_hex(bytes, f),
            Value::Counter32(n) | Value::Gauge32(n) | Value::TimeTicks(n) => write!(f, "{n}"),
            Value::Counter64(n) => write!(f, "{n}"),
        }
    }
}

/// Creates a `Value::OctetString` from a byte slice, copying the bytes.
///
/// # Examples
///
/// ```
/// use codec::Value;
///
/// let v = Value::from(b"hello".as_slice());
/// assert_eq!(v, Value::OctetString(b"hello".to_vec()));
/// ```
impl From<&[u8]> for Value {
    fn from(bytes: &[u8]) -> Self {
        Value::OctetString(bytes.to_vec())
    }
}

/// Creates a `Value::OctetString` from a `Vec<u8>`, taking ownership without copying.
///
/// # Examples
///
/// ```
/// use codec::Value;
///
/// let v = Value::from(vec![0x01u8, 0x02, 0x03]);
/// assert_eq!(v, Value::OctetString(vec![0x01, 0x02, 0x03]));
/// ```
impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Self {
        Value::OctetString(bytes)
    }
}

/// Creates a `Value::OctetString` from a string slice, encoding the UTF-8 bytes.
///
/// # Examples
///
/// ```
/// use codec::Value;
///
/// let v = Value::from("hello");
/// assert_eq!(v, Value::OctetString(b"hello".to_vec()));
/// ```
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::OctetString(s.as_bytes().to_vec())
    }
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
        let err = Oid::try_from(vec![0u32, 40]).unwrap_err();
        assert!(
            err.to_string().contains("second OID component"),
            "unexpected error: {err}"
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
        let err = "42".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("at least two components"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn oid_parse_error_empty_string() {
        let err = "".parse::<Oid>().unwrap_err();
        assert_eq!(err.to_string(), "invalid OID: empty string");
    }

    #[test]
    fn oid_parse_error_invalid_component() {
        let err = "1.3.foo.1".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("invalid component"),
            "unexpected error: {err}"
        );
        // The source error text must also appear in Display.
        assert!(
            err.to_string().contains("invalid digit found in string"),
            "expected chained source in Display, got: {err}"
        );
    }

    #[test]
    fn oid_parse_error_negative_component() {
        // Negative numbers are not valid OID components (u32 parse rejects them).
        let err = "1.3.-1".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("invalid component"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn oid_parse_error_invalid_first_component() {
        let err = "3.0".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("first OID component"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn oid_parse_error_second_component_too_large() {
        let err = "0.40".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("second OID component"),
            "unexpected error: {err}"
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
        let err = ".1.3.6".parse::<Oid>().unwrap_err();
        assert_eq!(err.to_string(), "invalid OID: leading dot");
    }

    #[test]
    fn oid_parse_error_trailing_dot() {
        let err = "1.3.6.".parse::<Oid>().unwrap_err();
        assert_eq!(err.to_string(), "invalid OID: trailing dot");
    }

    #[test]
    fn oid_parse_error_consecutive_dots() {
        let err = "1..3.6.1".parse::<Oid>().unwrap_err();
        assert!(
            err.to_string().contains("consecutive dots"),
            "unexpected error: {err}"
        );
    }

    // ".." starts with a dot, so it is reported as "leading dot" (the first
    // detected problem), not "consecutive dots".
    #[test]
    fn oid_parse_double_dot_only_reports_leading_dot() {
        let err = "..".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::LeadingDot);
        assert_eq!(err.to_string(), "invalid OID: leading dot");
    }

    // "1.." ends with a dot, so it is reported as "trailing dot", not
    // "consecutive dots".
    #[test]
    fn oid_parse_trailing_double_dot_reports_trailing_dot() {
        let err = "1..".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::TrailingDot);
        assert_eq!(err.to_string(), "invalid OID: trailing dot");
    }

    // --- Leading zero tests ---

    #[test]
    fn oid_parse_error_leading_zero_in_component() {
        let err = "1.3.06.1".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::LeadingZero);
        assert!(
            err.to_string().contains("leading zero"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("\"06\""),
            "expected component name in error, got: {err}"
        );
    }

    #[test]
    fn oid_parse_zero_components_are_valid() {
        // "1.0.0" has bare zero components, which are legitimate.
        assert!("1.0.0".parse::<Oid>().is_ok());
    }

    // --- OidErrorCategory tests ---

    #[test]
    fn oid_error_category_empty_string() {
        let err = "".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::EmptyString);
    }

    #[test]
    fn oid_error_category_invalid_component() {
        let err = "1.3.foo.1".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::InvalidComponent);
    }

    #[test]
    fn oid_error_category_too_few_components() {
        let err = "42".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::TooFewComponents);
    }

    #[test]
    fn oid_error_category_invalid_first_arc() {
        let err = "3.0".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::InvalidFirstArc);
    }

    #[test]
    fn oid_error_category_invalid_second_arc() {
        let err = "0.40".parse::<Oid>().unwrap_err();
        assert_eq!(err.category(), OidErrorCategory::InvalidSecondArc);
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
        let err = "".parse::<Oid>().unwrap_err();
        // Verify the trait bound is satisfied by using it as &dyn Error.
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn parse_oid_error_source_is_some_for_invalid_component() {
        use std::error::Error;
        let err = "1.3.foo".parse::<Oid>().unwrap_err();
        assert!(
            err.source().is_some(),
            "expected a chained source error for an invalid component"
        );
    }

    #[test]
    fn parse_oid_error_source_is_none_for_empty_string() {
        use std::error::Error;
        let err = "".parse::<Oid>().unwrap_err();
        assert!(
            err.source().is_none(),
            "expected no chained source error for an empty string"
        );
    }

    #[test]
    fn parse_oid_error_source_is_none_for_structural_violation() {
        use std::error::Error;
        let err = "3.0".parse::<Oid>().unwrap_err();
        assert!(
            err.source().is_none(),
            "expected no chained source error for a structural violation"
        );
    }

    // --- Value::Integer32 ---

    #[test]
    fn value_integer32_construction() {
        let Value::Integer32(n) = Value::Integer32(42) else {
            panic!("expected Integer32 variant");
        };
        assert_eq!(n, 42);
    }

    #[test]
    fn value_integer32_negative() {
        let v = Value::Integer32(-1);
        assert_eq!(v, Value::Integer32(-1));
    }

    #[test]
    fn value_integer32_display() {
        assert_eq!(Value::Integer32(0).to_string(), "0");
        assert_eq!(Value::Integer32(-32768).to_string(), "-32768");
    }

    // --- Value::IpAddress ---

    #[test]
    fn value_ip_address_construction() {
        let Value::IpAddress(octets) = Value::IpAddress([192, 168, 1, 1]) else {
            panic!("expected IpAddress variant");
        };
        assert_eq!(octets, [192, 168, 1, 1]);
    }

    #[test]
    fn value_ip_address_display_dotted_decimal() {
        let v = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(v.to_string(), "192.168.1.1");
    }

    #[test]
    fn value_ip_address_display_all_zeros() {
        assert_eq!(Value::IpAddress([0, 0, 0, 0]).to_string(), "0.0.0.0");
    }

    #[test]
    fn value_ip_address_display_broadcast() {
        assert_eq!(
            Value::IpAddress([255, 255, 255, 255]).to_string(),
            "255.255.255.255"
        );
    }

    // --- Value::ObjectIdentifier ---

    #[test]
    fn value_object_identifier_construction() {
        let oid = Oid::from_slice(&[1, 3, 6, 1]);
        let Value::ObjectIdentifier(inner) = Value::ObjectIdentifier(oid) else {
            panic!("expected ObjectIdentifier variant");
        };
        assert_eq!(inner.as_slice(), &[1, 3, 6, 1]);
    }

    #[test]
    fn value_object_identifier_display() {
        let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let v = Value::ObjectIdentifier(oid);
        assert_eq!(v.to_string(), "1.3.6.1.2.1");
    }

    // --- Value::OctetString ---

    #[test]
    fn value_octet_string_construction() {
        let Value::OctetString(bytes) = Value::OctetString(b"hello".to_vec()) else {
            panic!("expected OctetString variant");
        };
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn value_octet_string_display() {
        let v = Value::OctetString(b"Hello".to_vec());
        assert_eq!(v.to_string(), "48656C6C6F");
    }

    #[test]
    fn value_octet_string_display_empty() {
        assert_eq!(Value::OctetString(vec![]).to_string(), "");
    }

    #[test]
    fn value_octet_string_display_single_byte() {
        assert_eq!(Value::OctetString(vec![0x0F]).to_string(), "0F");
    }

    // --- Value::Counter32 ---

    #[test]
    fn value_counter32_construction() {
        let Value::Counter32(n) = Value::Counter32(1234) else {
            panic!("expected Counter32 variant");
        };
        assert_eq!(n, 1234);
    }

    #[test]
    fn value_counter32_display() {
        assert_eq!(Value::Counter32(0).to_string(), "0");
        assert_eq!(Value::Counter32(42).to_string(), "42");
    }

    #[test]
    fn value_counter32_display_max() {
        assert_eq!(Value::Counter32(u32::MAX).to_string(), u32::MAX.to_string());
    }

    // --- Value::Counter64 ---

    #[test]
    fn value_counter64_construction() {
        let Value::Counter64(n) = Value::Counter64(u64::MAX) else {
            panic!("expected Counter64 variant");
        };
        assert_eq!(n, u64::MAX);
    }

    #[test]
    fn value_counter64_display() {
        assert_eq!(Value::Counter64(0).to_string(), "0");
        assert_eq!(Value::Counter64(1_000_000).to_string(), "1000000");
    }

    #[test]
    fn value_counter64_display_max() {
        assert_eq!(Value::Counter64(u64::MAX).to_string(), u64::MAX.to_string());
    }

    // --- Value::Gauge32 ---

    #[test]
    fn value_gauge32_construction() {
        let Value::Gauge32(n) = Value::Gauge32(500) else {
            panic!("expected Gauge32 variant");
        };
        assert_eq!(n, 500);
    }

    #[test]
    fn value_gauge32_display() {
        assert_eq!(Value::Gauge32(0).to_string(), "0");
        assert_eq!(Value::Gauge32(100).to_string(), "100");
    }

    #[test]
    fn value_gauge32_display_max() {
        assert_eq!(Value::Gauge32(u32::MAX).to_string(), u32::MAX.to_string());
    }

    // --- Value::TimeTicks ---

    #[test]
    fn value_timeticks_construction() {
        let Value::TimeTicks(n) = Value::TimeTicks(360_000) else {
            panic!("expected TimeTicks variant");
        };
        // 360_000 hundredths of a second = 1 hour.
        assert_eq!(n, 360_000);
    }

    #[test]
    fn value_timeticks_display() {
        assert_eq!(Value::TimeTicks(0).to_string(), "0");
        assert_eq!(Value::TimeTicks(100).to_string(), "100");
    }

    #[test]
    fn value_timeticks_display_max() {
        assert_eq!(Value::TimeTicks(u32::MAX).to_string(), u32::MAX.to_string());
    }

    // --- Value::Opaque ---

    #[test]
    fn value_opaque_construction() {
        let Value::Opaque(bytes) = Value::Opaque(vec![0xDE, 0xAD, 0xBE, 0xEF]) else {
            panic!("expected Opaque variant");
        };
        assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn value_opaque_display() {
        let v = Value::Opaque(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(v.to_string(), "DEADBEEF");
    }

    #[test]
    fn value_opaque_display_empty() {
        assert_eq!(Value::Opaque(vec![]).to_string(), "");
    }

    #[test]
    fn value_opaque_display_single_byte_low_nibble() {
        // Ensures zero-padding of the high nibble.
        assert_eq!(Value::Opaque(vec![0x0A]).to_string(), "0A");
    }

    // --- Value From conversions ---

    #[test]
    fn value_from_byte_slice() {
        let v = Value::from(b"hello".as_slice());
        assert_eq!(v, Value::OctetString(b"hello".to_vec()));
    }

    #[test]
    fn value_from_byte_slice_empty() {
        let v = Value::from([].as_slice());
        assert_eq!(v, Value::OctetString(vec![]));
    }

    #[test]
    fn value_from_vec_u8() {
        let bytes = vec![0x01u8, 0x02, 0x03];
        let v = Value::from(bytes);
        assert_eq!(v, Value::OctetString(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn value_from_vec_u8_empty() {
        let v = Value::from(vec![]);
        assert_eq!(v, Value::OctetString(vec![]));
    }

    #[test]
    fn value_from_str_slice() {
        let v = Value::from("hello");
        assert_eq!(v, Value::OctetString(b"hello".to_vec()));
    }

    #[test]
    fn value_from_str_slice_empty() {
        let v = Value::from("");
        assert_eq!(v, Value::OctetString(vec![]));
    }

    #[test]
    fn value_from_str_slice_utf8() {
        // Non-ASCII UTF-8 encodes to multiple bytes per character.
        let v = Value::from("é");
        assert_eq!(v, Value::OctetString("é".as_bytes().to_vec()));
    }
}
