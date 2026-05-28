//! USM key derivation functions: password-to-key.
//!
//! # Requirements
//! Implements: REQ-0081, REQ-0082, REQ-0108

use std::fmt;

use sha2::{Digest, Sha256, Sha512};

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::{SecretKey, zeroize_slice};

// The RFC 3414 §2.6 mandated stream length for the password-to-key algorithm.
const KDF_STREAM_LEN: usize = 0x0010_0000;

// ── Error type ────────────────────────────────────────────────────────────────

/// Error returned when key derivation fails due to invalid password input.
///
/// # Requirements
/// Implements: REQ-0090
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// The password is empty.
    EmptyPassword,
    /// The password is shorter than 8 bytes (RFC 3414 §11.2 minimum).
    PasswordTooShort { length: usize },
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassword => write!(f, "USM password must not be empty per RFC 3414"),
            Self::PasswordTooShort { length } => write!(
                f,
                "USM password must be at least 8 bytes per RFC 3414 §11.2, got {length}"
            ),
        }
    }
}

impl std::error::Error for KdfError {}

// ── Public functions ──────────────────────────────────────────────────────────

/// Derive a localised USM key from a passphrase and an engine identifier.
///
/// Implements the RFC 3414 §2.6 password-to-key algorithm extended to
/// SHA-2 per RFC 7860 §2:
/// 1. Hash a 1 MiB stream formed by repeating `password` cyclically with
///    the protocol's underlying hash (SHA-256 or SHA-512) to produce a
///    master key `Ku`.
/// 2. Localise: `Kul = H(Ku || engineID || Ku)`, truncated to
///    `protocol.key_len()` bytes.
///
/// If `password` is longer than 1,048,576 bytes, only the first 1,048,576
/// bytes are effectively used: the cyclic repetition produces at most one
/// full or partial copy of the password within the stream length.
///
/// # Errors
/// Returns [`KdfError::EmptyPassword`] if `password` is empty.
/// Returns [`KdfError::PasswordTooShort`] if `password` is shorter than 8
/// bytes (RFC 3414 §11.2 minimum).
///
/// # Requirements
/// Implements: REQ-0081, REQ-0082, REQ-0108, REQ-0114
pub fn password_to_localised_key(
    password: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> Result<SecretKey, KdfError> {
    if password.is_empty() {
        return Err(KdfError::EmptyPassword);
    }
    if password.len() < 8 {
        return Err(KdfError::PasswordTooShort {
            length: password.len(),
        });
    }

    // Step 1: hash a 1 MiB stream of cyclically repeated password bytes.
    // The stream length of 2^20 bytes is mandated by RFC 3414 §2.6 and
    // RFC 7860 §2 to provide adequate work against dictionary attacks.
    // Streaming into the hasher avoids materialising the 1 MiB buffer.
    let full_copies = KDF_STREAM_LEN / password.len();
    let remainder_len = KDF_STREAM_LEN % password.len();
    // remainder_len < password.len() by definition of modulo (password is non-empty per check above)
    let (final_chunk, _) = password.split_at(remainder_len);
    // master_key holds Ku inside a SecretKey so it is zeroised on drop.
    let master_key: SecretKey = match protocol {
        AuthProtocol::HmacSha256 => {
            let mut hasher = Sha256::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(final_chunk);
            finalise_into_secret_key(hasher)
        }
        AuthProtocol::HmacSha512 => {
            let mut hasher = Sha512::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(final_chunk);
            finalise_into_secret_key(hasher)
        }
    };

    // Step 2: localise by hashing the concatenation Ku || engineID || Ku.
    // RFC 3414 §2.6 specifies H(Ku || snmpEngineID || Ku) — a plain hash,
    // not an HMAC. RFC 7860 §2 extends this to SHA-256/SHA-512 using the
    // same plain-hash formula.
    let mut localised = localise_key(master_key.as_bytes(), engine_id, protocol);
    localised.truncate(protocol.key_len());
    Ok(localised)
}

// ── Private helpers ───────────────────────────────────────────────────────────

// Finalise a hasher and move its output into a SecretKey, then zeroise the
// stack-local GenericArray digest. The hasher's internal state is *not*
// zeroised because the sha2 crate does not expose a way to clear it; this
// is a known limitation — the hasher state lives on the stack and is
// overwritten promptly by subsequent frames, but is not defence-in-depth
// guaranteed.
// Implements: REQ-0108
fn finalise_into_secret_key<D: Digest>(hasher: D) -> SecretKey {
    let mut digest = hasher.finalize();
    let mut key = SecretKey::zeroed(digest.len());
    key.as_bytes_mut().copy_from_slice(&digest);
    zeroize_slice(digest.as_mut_slice());
    key
}

// Compute H(key || engine_id || key) per RFC 3414 §2.6 / RFC 3826 §2.1.
// Returns the full hash digest inside a SecretKey so intermediate material
// is zeroised on drop. Callers truncate to their required length.
// Implements: REQ-0082, REQ-0108
fn localise_key(key: &[u8], engine_id: &[u8], protocol: AuthProtocol) -> SecretKey {
    match protocol {
        AuthProtocol::HmacSha256 => {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(engine_id);
            hasher.update(key);
            finalise_into_secret_key(hasher)
        }
        AuthProtocol::HmacSha512 => {
            let mut hasher = Sha512::new();
            hasher.update(key);
            hasher.update(engine_id);
            hasher.update(key);
            finalise_into_secret_key(hasher)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MAPLE_ENGINE_ID: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn given_password_when_derive_sha256_key_then_returns_32_bytes() {
        // Verifies: REQ-0081
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_password_when_derive_sha512_key_then_returns_64_bytes() {
        // Verifies: REQ-0081
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512)
                .unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn given_same_password_and_engine_id_when_derive_twice_then_same_key() {
        // Verifies: REQ-0081 — deterministic
        let key_a =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        let key_b =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        assert_eq!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_engine_ids_when_derive_then_different_keys() {
        // Verifies: REQ-0082 — engine ID localises the key
        let engine_id_a = &[0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let engine_id_b = &[0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key_a = password_to_localised_key(b"passphrase", engine_id_a, AuthProtocol::HmacSha256)
            .unwrap();
        let key_b = password_to_localised_key(b"passphrase", engine_id_b, AuthProtocol::HmacSha256)
            .unwrap();
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_passwords_when_derive_then_different_keys() {
        // Verifies: REQ-0081 — distinct passwords produce distinct keys
        let key_a =
            password_to_localised_key(b"password_one", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        let key_b =
            password_to_localised_key(b"password_two", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_known_password_and_engine_id_when_derive_sha256_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using the RFC 3414 §2.6 algorithm H(Ku || eid || Ku),
        // validated against the RFC 3414 §A.3.1 MD5 and §A.3.2 SHA-1 test vectors
        // (same algorithm, different hash function):
        //   import hashlib
        //   pw = b"maplesyrup"
        //   stream_len = 1048576
        //   full_copies = stream_len // len(pw)
        //   remainder = stream_len % len(pw)
        //   h = hashlib.sha256()
        //   for _ in range(full_copies): h.update(pw)
        //   h.update(pw[:remainder])
        //   ku = h.digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   kul = hashlib.sha256(ku + engine_id + ku).digest()
        //   # => 8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        let expected: [u8; 32] = [
            0x89, 0x82, 0xe0, 0xe5, 0x49, 0xe8, 0x66, 0xdb, 0x36, 0x1a, 0x6b, 0x62, 0x5d, 0x84,
            0xcc, 0xcc, 0x11, 0x16, 0x2d, 0x45, 0x3e, 0xe8, 0xce, 0x3a, 0x64, 0x45, 0xc2, 0xd6,
            0x77, 0x6f, 0x0f, 0x8b,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_known_password_and_engine_id_when_derive_sha512_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using the RFC 3414 §2.6 algorithm H(Ku || eid || Ku),
        // validated against the RFC 3414 §A.3.1 MD5 and §A.3.2 SHA-1 test vectors:
        //   import hashlib
        //   pw = b"maplesyrup"
        //   stream_len = 1048576
        //   full_copies = stream_len // len(pw)
        //   remainder = stream_len % len(pw)
        //   h = hashlib.sha512()
        //   for _ in range(full_copies): h.update(pw)
        //   h.update(pw[:remainder])
        //   ku = h.digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   kul = hashlib.sha512(ku + engine_id + ku).digest()
        //   # => 22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099
        //   #    ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512)
                .unwrap();
        let expected: [u8; 64] = [
            0x22, 0xa5, 0xa3, 0x6c, 0xed, 0xfc, 0xc0, 0x85, 0x80, 0x7a, 0x12, 0x8d, 0x7b, 0xc6,
            0xc2, 0x38, 0x21, 0x67, 0xad, 0x6c, 0x0d, 0xbc, 0x5f, 0xdf, 0xf8, 0x56, 0x74, 0x0f,
            0x3d, 0x84, 0xc0, 0x99, 0xad, 0x1e, 0xa8, 0x7a, 0x8d, 0xb0, 0x96, 0x71, 0x4d, 0x97,
            0x88, 0xbd, 0x54, 0x40, 0x47, 0xc9, 0x02, 0x1e, 0x42, 0x29, 0xce, 0x27, 0xe4, 0xc0,
            0xa6, 0x92, 0x50, 0xad, 0xfc, 0xff, 0xbb, 0x0b,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_single_byte_password_when_derive_sha256_key_then_error() {
        // Verifies: REQ-0090, REQ-0114
        // The single-byte password "x" is below the RFC 3414 §11.2 minimum of
        // 8 bytes, so the function must reject it rather than produce a key.
        let result = password_to_localised_key(b"x", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert!(matches!(
            result.unwrap_err(),
            KdfError::PasswordTooShort { length: 1 }
        ));
    }

    #[test]
    fn given_password_longer_than_stream_when_derive_then_same_length_key() {
        // Verifies: REQ-0081
        let long_password = vec![0x42_u8; 2_000_000]; // longer than 1 MiB
        let key =
            password_to_localised_key(&long_password, MAPLE_ENGINE_ID, AuthProtocol::HmacSha256)
                .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_empty_password_when_derive_then_error() {
        // Verifies: REQ-0114
        let result =
            password_to_localised_key(b"", b"\x80\x00\x1f\x88\x04test", AuthProtocol::HmacSha256);
        assert_eq!(result.unwrap_err(), KdfError::EmptyPassword);
    }

    #[test]
    fn given_7_byte_password_when_derive_then_error() {
        // Verifies: REQ-0114
        let result = password_to_localised_key(
            b"short!!",
            b"\x80\x00\x1f\x88\x04test",
            AuthProtocol::HmacSha256,
        );
        assert!(matches!(
            result.unwrap_err(),
            KdfError::PasswordTooShort { length: 7 }
        ));
    }

    #[test]
    fn given_8_byte_password_when_derive_then_ok() {
        // Verifies: REQ-0114
        let result = password_to_localised_key(
            b"exactly8",
            b"\x80\x00\x1f\x88\x04test",
            AuthProtocol::HmacSha256,
        );
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn given_kdf_error_empty_password_when_displayed_then_shows_rfc_message() {
        // Verifies: REQ-0090
        // Exercises KdfError::fmt — a mutant replacing fmt with () would produce
        // an empty string, causing this assertion to fail.
        let error = KdfError::EmptyPassword;
        assert_eq!(
            error.to_string(),
            "USM password must not be empty per RFC 3414",
        );
    }

    #[test]
    fn given_kdf_error_too_short_when_displayed_then_includes_length_in_message() {
        // Verifies: REQ-0090
        let error = KdfError::PasswordTooShort { length: 5 };
        assert_eq!(
            error.to_string(),
            "USM password must be at least 8 bytes per RFC 3414 §11.2, got 5",
        );
    }
}
