//! USM authentication protocols: HMAC-SHA-256 and HMAC-SHA-512.
//!
//! # Requirements
//! Implements: REQ-0083, REQ-0086, REQ-0087

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::usm::keys::SecretKey;

// ── AuthProtocol ─────────────────────────────────────────────────────────────

/// USM authentication protocol.
///
/// Determines the HMAC algorithm used to authenticate messages and the
/// required localised key length.
///
/// # Requirements
/// Implements: REQ-0083, REQ-0086, REQ-0087
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    /// `usmHMAC192SHA256AuthProtocol`: HMAC-SHA-256 with 192-bit (24-byte) MAC
    /// truncation, as defined in RFC 7860 §4.1.
    ///
    /// Localised key length: 32 bytes. This is the mandatory-to-implement
    /// authentication protocol.
    HmacSha256,

    /// `usmHMAC384SHA512AuthProtocol`: HMAC-SHA-512 with 384-bit (48-byte) MAC
    /// truncation, as defined in RFC 7860 §4.4.
    ///
    /// Localised key length: 64 bytes.
    HmacSha512,
}

impl AuthProtocol {
    /// Return the required localised key length in bytes for this protocol.
    ///
    /// 32 bytes for [`HmacSha256`][AuthProtocol::HmacSha256],
    /// 64 bytes for [`HmacSha512`][AuthProtocol::HmacSha512].
    ///
    /// # Requirements
    /// Implements: REQ-0083
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::HmacSha256 => 32,
            Self::HmacSha512 => 64,
        }
    }

    /// Return the MAC truncation length in bytes for this protocol.
    ///
    /// 24 bytes (192 bits) for HMAC-SHA-256 per RFC 7860 §4.1.
    /// 48 bytes (384 bits) for HMAC-SHA-512 per RFC 7860 §4.4.
    ///
    /// # Requirements
    /// Implements: REQ-0086, REQ-0087
    #[must_use]
    pub fn mac_len(self) -> usize {
        match self {
            Self::HmacSha256 => 24,
            Self::HmacSha512 => 48,
        }
    }

    /// Compute the truncated HMAC over `message` using `key`.
    ///
    /// Returns `Err` if `key` is not exactly [`key_len`][Self::key_len] bytes.
    ///
    /// # Requirements
    /// Implements: REQ-0083, REQ-0086, REQ-0087
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKeyLength`] if the key length does not match
    /// the protocol's required length.
    pub fn compute_mac(self, key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, AuthError> {
        if key.len() != self.key_len() {
            return Err(AuthError::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        let mac = match self {
            Self::HmacSha256 => {
                // `new_from_slice` only fails if the key is empty for some
                // digest types; HMAC accepts any key length, so this is
                // unreachable after the length check above.
                let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                    .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                hmac.update(message);
                hmac.finalize().into_bytes().to_vec()
            }
            Self::HmacSha512 => {
                let mut hmac = Hmac::<Sha512>::new_from_slice(key.as_bytes())
                    .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                hmac.update(message);
                hmac.finalize().into_bytes().to_vec()
            }
        };
        Ok(mac[..self.mac_len()].to_vec())
    }

    /// Verify a truncated HMAC over `message` using `key`.
    ///
    /// Returns `Ok(())` if the MAC is valid, or `Err` if it is invalid or the
    /// key length is wrong.
    ///
    /// # Requirements
    /// Implements: REQ-0083, REQ-0086, REQ-0087
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidKeyLength`] if the key length does not match
    /// the protocol's required length, or [`AuthError::MacMismatch`] if the
    /// MAC does not match.
    pub fn verify_mac(
        self,
        key: &SecretKey,
        message: &[u8],
        expected_mac: &[u8],
    ) -> Result<(), AuthError> {
        if key.len() != self.key_len() {
            return Err(AuthError::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        // Uses the `hmac` crate's constant-time `verify_truncated_left`, which
        // compares the leftmost N bytes of the computed MAC via the `subtle`
        // crate. RFC 7860 specifies left-truncation for both HMAC-SHA-256 and
        // HMAC-SHA-512.
        let result = match self {
            Self::HmacSha256 => {
                let mut h = Hmac::<Sha256>::new_from_slice(key.as_bytes())
                    .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                h.update(message);
                h.verify_truncated_left(expected_mac)
            }
            Self::HmacSha512 => {
                let mut h = Hmac::<Sha512>::new_from_slice(key.as_bytes())
                    .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
                h.update(message);
                h.verify_truncated_left(expected_mac)
            }
        };
        result.map_err(|_| AuthError::MacMismatch)
    }
}

// ── AuthError ────────────────────────────────────────────────────────────────

/// Error type for authentication operations.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The supplied key has the wrong length for the authentication protocol.
    InvalidKeyLength { expected: usize, actual: usize },
    /// The MAC did not match.
    MacMismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => write!(
                f,
                "invalid authentication key length: expected {expected} bytes, got {actual}"
            ),
            Self::MacMismatch => write!(f, "authentication MAC mismatch"),
        }
    }
}

impl std::error::Error for AuthError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── key_len ───────────────────────────────────────────────────────────────

    #[test]
    fn hmac_sha256_key_len_is_32() {
        // Verifies: REQ-0083
        assert_eq!(AuthProtocol::HmacSha256.key_len(), 32);
    }

    #[test]
    fn hmac_sha512_key_len_is_64() {
        // Verifies: REQ-0083
        assert_eq!(AuthProtocol::HmacSha512.key_len(), 64);
    }

    // ── mac_len ───────────────────────────────────────────────────────────────

    #[test]
    fn hmac_sha256_mac_len_is_24() {
        // Verifies: REQ-0086
        assert_eq!(AuthProtocol::HmacSha256.mac_len(), 24);
    }

    #[test]
    fn hmac_sha512_mac_len_is_48() {
        // Verifies: REQ-0087
        assert_eq!(AuthProtocol::HmacSha512.mac_len(), 48);
    }

    // ── compute_mac ───────────────────────────────────────────────────────────

    #[test]
    fn given_correct_key_when_compute_sha256_mac_then_returns_24_bytes() {
        // Verifies: REQ-0086
        let key = SecretKey::new(vec![0xABu8; 32]);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, b"hello")
            .unwrap();
        assert_eq!(mac.len(), 24);
    }

    #[test]
    fn given_correct_key_when_compute_sha512_mac_then_returns_48_bytes() {
        // Verifies: REQ-0087
        let key = SecretKey::new(vec![0xCDu8; 64]);
        let mac = AuthProtocol::HmacSha512
            .compute_mac(&key, b"hello")
            .unwrap();
        assert_eq!(mac.len(), 48);
    }

    #[test]
    fn given_wrong_key_length_when_compute_sha256_mac_then_error() {
        // Verifies: REQ-0083
        let key = SecretKey::new(vec![0u8; 16]); // 16 bytes, not 32
        let result = AuthProtocol::HmacSha256.compute_mac(&key, b"hello");
        assert_eq!(
            result,
            Err(AuthError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            })
        );
    }

    #[test]
    fn given_wrong_key_length_when_compute_sha512_mac_then_error() {
        // Verifies: REQ-0083
        let key = SecretKey::new(vec![0u8; 32]); // 32 bytes, not 64
        let result = AuthProtocol::HmacSha512.compute_mac(&key, b"hello");
        assert_eq!(
            result,
            Err(AuthError::InvalidKeyLength {
                expected: 64,
                actual: 32,
            })
        );
    }

    #[test]
    fn given_same_message_and_key_when_compute_mac_twice_then_same_result() {
        // Verifies: REQ-0086 — MAC is deterministic
        let key = SecretKey::new(vec![0x11u8; 32]);
        let mac1 = AuthProtocol::HmacSha256
            .compute_mac(&key, b"test message")
            .unwrap();
        let mac2 = AuthProtocol::HmacSha256
            .compute_mac(&key, b"test message")
            .unwrap();
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn given_different_messages_when_compute_mac_then_different_results() {
        // Verifies: REQ-0086
        let key = SecretKey::new(vec![0x22u8; 32]);
        let mac1 = AuthProtocol::HmacSha256
            .compute_mac(&key, b"message one")
            .unwrap();
        let mac2 = AuthProtocol::HmacSha256
            .compute_mac(&key, b"message two")
            .unwrap();
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn given_known_key_and_message_when_compute_sha256_mac_then_matches_reference_vector() {
        // Verifies: REQ-0086
        // Expected value computed by Python's hmac module (stdlib) with
        // key=[0x0b]*32, msg=b"Hi There". Serves as a regression guard;
        // full interoperability is verified by the Behave system tests.
        let key = SecretKey::new(vec![0x0Bu8; 32]);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, b"Hi There")
            .unwrap();
        let expected: [u8; 24] = [
            25, 138, 96, 126, 180, 75, 251, 198, 153, 3, 160, 241, 207, 43, 189, 197, 186, 10, 163,
            243, 217, 174, 60, 28,
        ];
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    #[test]
    fn given_known_key_and_message_when_compute_sha512_mac_then_matches_reference_vector() {
        // Verifies: REQ-0087
        // Expected value computed by Python's hmac module (stdlib) with
        // key=[0x0b]*64, msg=b"Hi There". Serves as a regression guard;
        // full interoperability is verified by the Behave system tests.
        let key = SecretKey::new(vec![0x0Bu8; 64]);
        let mac = AuthProtocol::HmacSha512
            .compute_mac(&key, b"Hi There")
            .unwrap();
        let expected: [u8; 48] = [
            99, 126, 220, 110, 1, 220, 231, 230, 116, 42, 153, 69, 26, 174, 130, 223, 35, 218, 62,
            146, 67, 158, 89, 14, 67, 231, 97, 179, 62, 145, 15, 184, 172, 40, 120, 235, 213, 128,
            63, 111, 11, 97, 219, 206, 94, 37, 31, 248,
        ];
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    // ── verify_mac ────────────────────────────────────────────────────────────

    #[test]
    fn given_valid_mac_when_verify_sha256_then_ok() {
        // Verifies: REQ-0086
        let key = SecretKey::new(vec![0x33u8; 32]);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, b"verify me")
            .unwrap();
        assert_eq!(
            AuthProtocol::HmacSha256.verify_mac(&key, b"verify me", &mac),
            Ok(())
        );
    }

    #[test]
    fn given_valid_mac_when_verify_sha512_then_ok() {
        // Verifies: REQ-0087
        let key = SecretKey::new(vec![0x44u8; 64]);
        let mac = AuthProtocol::HmacSha512
            .compute_mac(&key, b"verify me")
            .unwrap();
        assert_eq!(
            AuthProtocol::HmacSha512.verify_mac(&key, b"verify me", &mac),
            Ok(())
        );
    }

    #[test]
    fn given_tampered_mac_when_verify_then_mac_mismatch_error() {
        // Verifies: REQ-0086
        let key = SecretKey::new(vec![0x55u8; 32]);
        let mut mac = AuthProtocol::HmacSha256
            .compute_mac(&key, b"authentic")
            .unwrap();
        mac[0] ^= 0xFF; // flip a byte
        assert_eq!(
            AuthProtocol::HmacSha256.verify_mac(&key, b"authentic", &mac),
            Err(AuthError::MacMismatch)
        );
    }

    #[test]
    fn given_tampered_message_when_verify_then_mac_mismatch_error() {
        // Verifies: REQ-0086
        let key = SecretKey::new(vec![0x66u8; 32]);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, b"original")
            .unwrap();
        assert_eq!(
            AuthProtocol::HmacSha256.verify_mac(&key, b"tampered", &mac),
            Err(AuthError::MacMismatch)
        );
    }

    #[test]
    fn given_wrong_key_when_verify_then_error() {
        // Verifies: REQ-0083
        let key = SecretKey::new(vec![0u8; 16]);
        let mac = vec![0u8; 24];
        assert_eq!(
            AuthProtocol::HmacSha256.verify_mac(&key, b"msg", &mac),
            Err(AuthError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            })
        );
    }

    // ── error display ─────────────────────────────────────────────────────────

    #[test]
    fn auth_error_invalid_key_length_display() {
        let e = AuthError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            e.to_string(),
            "invalid authentication key length: expected 32 bytes, got 16"
        );
    }

    #[test]
    fn auth_error_mac_mismatch_display() {
        let e = AuthError::MacMismatch;
        assert_eq!(e.to_string(), "authentication MAC mismatch");
    }

    #[test]
    fn auth_error_implements_std_error() {
        let e: &dyn std::error::Error = &AuthError::MacMismatch;
        assert!(e.source().is_none());
    }
}
