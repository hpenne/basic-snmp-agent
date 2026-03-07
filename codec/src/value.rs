//! `SMIv2` value types for SNMP varbinds.

use std::fmt;

use crate::Oid;

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
