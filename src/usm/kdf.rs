//! USM key derivation functions: password-to-key and privacy key derivation.
//!
//! # Requirements
//! Implements: REQ-0081, REQ-0082

use sha2::{Digest, Sha256, Sha512};

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::SecretKey;
use crate::usm::privacy::PrivProtocol;

// The RFC 3414 §2.6 mandated stream length for the password-to-key algorithm.
const KDF_STREAM_LEN: usize = 1_048_576;

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
/// # Requirements
/// Implements: REQ-0081, REQ-0082
///
/// # Panics
/// Panics if `password` is empty.
#[must_use]
pub fn password_to_localised_key(
    password: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> SecretKey {
    assert!(
        !password.is_empty(),
        "USM password must not be empty per RFC 3414"
    );

    // Step 1: hash a 1 MiB stream of cyclically repeated password bytes.
    // The stream length of 2^20 bytes is mandated by RFC 3414 §2.6 and
    // RFC 7860 §2 to provide adequate work against dictionary attacks.
    // Streaming into the hasher avoids materialising the 1 MiB buffer.
    let full_copies = KDF_STREAM_LEN / password.len();
    let remainder = KDF_STREAM_LEN % password.len();
    let master_key_bytes: Vec<u8> = match protocol {
        AuthProtocol::HmacSha256 => {
            let mut hasher = Sha256::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(&password[..remainder]);
            hasher.finalize().to_vec()
        }
        AuthProtocol::HmacSha512 => {
            let mut hasher = Sha512::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(&password[..remainder]);
            hasher.finalize().to_vec()
        }
    };

    // Step 2: localise by hashing the concatenation Ku || engineID || Ku.
    // RFC 3414 §2.6 specifies H(Ku || snmpEngineID || Ku) — a plain hash,
    // not an HMAC. RFC 7860 §2 extends this to SHA-256/SHA-512 using the
    // same plain-hash formula.
    let localised_bytes = localise_key(&master_key_bytes, engine_id, protocol);
    SecretKey::new(localised_bytes[..protocol.key_len()].to_vec())
}

/// Derive a USM privacy key from a localised authentication key.
///
/// Implements RFC 3826 §2.1: the privacy key is derived by computing
/// `H(auth_key || engineID || auth_key)` and taking the first
/// `priv_protocol.key_len()` bytes of the full hash output.
///
/// Using the full (non-truncated) hash output before slicing ensures
/// AES-256 can obtain its required 32 bytes even when the auth protocol's
/// hash output length is equal to or shorter than needed.
///
/// # Requirements
/// Implements: REQ-0081, REQ-0082
#[must_use]
pub fn derive_priv_key_from_auth_key(
    auth_key: &SecretKey,
    engine_id: &[u8],
    auth_protocol: AuthProtocol,
    priv_protocol: PrivProtocol,
) -> SecretKey {
    // RFC 3826 §2.1 uses the same plain-hash localisation formula as
    // RFC 3414 §2.6: H(key || engineID || key).
    let full_hash = localise_key(auth_key.as_bytes(), engine_id, auth_protocol);
    SecretKey::new(full_hash[..priv_protocol.key_len()].to_vec())
}

// ── Private helpers ───────────────────────────────────────────────────────────

// Compute H(key || engine_id || key) per RFC 3414 §2.6 / RFC 3826 §2.1.
// Returns the full hash digest so callers can truncate to their required length.
// Implements: REQ-0082
fn localise_key(key: &[u8], engine_id: &[u8], protocol: AuthProtocol) -> Vec<u8> {
    match protocol {
        AuthProtocol::HmacSha256 => {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(engine_id);
            hasher.update(key);
            hasher.finalize().to_vec()
        }
        AuthProtocol::HmacSha512 => {
            let mut hasher = Sha512::new();
            hasher.update(key);
            hasher.update(engine_id);
            hasher.update(key);
            hasher.finalize().to_vec()
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
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_password_when_derive_sha512_key_then_returns_64_bytes() {
        // Verifies: REQ-0081
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn given_same_password_and_engine_id_when_derive_twice_then_same_key() {
        // Verifies: REQ-0081 — deterministic
        let key_a =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let key_b =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_engine_ids_when_derive_then_different_keys() {
        // Verifies: REQ-0082 — engine ID localises the key
        let engine_id_a = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let engine_id_b = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key_a = password_to_localised_key(b"passphrase", engine_id_a, AuthProtocol::HmacSha256);
        let key_b = password_to_localised_key(b"passphrase", engine_id_b, AuthProtocol::HmacSha256);
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_passwords_when_derive_then_different_keys() {
        // Verifies: REQ-0081 — distinct passwords produce distinct keys
        let key_a =
            password_to_localised_key(b"password_one", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let key_b =
            password_to_localised_key(b"password_two", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
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
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
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
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512);
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
    fn given_auth_key_when_derive_priv_key_aes128_then_returns_16_bytes() {
        // Verifies: REQ-0082
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key.len(), 16);
    }

    #[test]
    fn given_auth_key_when_derive_priv_key_aes256_then_returns_32_bytes() {
        // Verifies: REQ-0082
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
    }

    #[test]
    fn given_sha512_auth_key_when_derive_priv_key_aes128_then_returns_16_bytes() {
        // Verifies: REQ-0082 — SHA-512 auth with AES-128 priv
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key.len(), 16);
    }

    #[test]
    fn given_sha512_auth_key_when_derive_priv_key_aes256_then_returns_32_bytes() {
        // Verifies: REQ-0082 — SHA-512 auth with AES-256 priv
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
    }

    #[test]
    fn given_same_auth_key_and_engine_id_when_derive_priv_twice_then_same() {
        // Verifies: REQ-0082 — deterministic
        let auth_key_a = SecretKey::new(vec![0x77u8; 32]);
        let auth_key_b = SecretKey::new(vec![0x77u8; 32]);
        let priv_key_a = derive_priv_key_from_auth_key(
            &auth_key_a,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let priv_key_b = derive_priv_key_from_auth_key(
            &auth_key_b,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key_a.as_bytes(), priv_key_b.as_bytes());
    }

    #[test]
    fn given_different_engine_ids_when_derive_priv_then_different_keys() {
        // Verifies: REQ-0082 — engine ID localises the privacy key
        let auth_key_a = SecretKey::new(vec![0x55u8; 32]);
        let auth_key_b = SecretKey::new(vec![0x55u8; 32]);
        let engine_id_a = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let engine_id_b = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let priv_key_a = derive_priv_key_from_auth_key(
            &auth_key_a,
            engine_id_a,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let priv_key_b = derive_priv_key_from_auth_key(
            &auth_key_b,
            engine_id_b,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_ne!(priv_key_a.as_bytes(), priv_key_b.as_bytes());
    }

    #[test]
    fn given_known_auth_key_and_engine_id_when_derive_priv_key_sha256_aes128_then_matches_reference()
     {
        // Verifies: REQ-0082
        // Reference computed using the RFC 3826 §2.1 algorithm H(auth_key || eid || auth_key),
        // validated against the RFC 3414 §A.3.1 MD5 and §A.3.2 SHA-1 test vectors:
        //   import hashlib
        //   auth_key = bytes([0xAB] * 32)
        //   engine_id = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        //   full_hash = hashlib.sha256(auth_key + engine_id + auth_key).digest()
        //   priv_key_aes128 = full_hash[:16]
        //   # => f2a0859a33e22a9b5a42af5847f1699e
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let expected: [u8; 16] = [
            0xf2, 0xa0, 0x85, 0x9a, 0x33, 0xe2, 0x2a, 0x9b, 0x5a, 0x42, 0xaf, 0x58, 0x47, 0xf1,
            0x69, 0x9e,
        ];
        assert_eq!(priv_key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_known_auth_key_and_engine_id_when_derive_priv_key_sha512_aes256_then_matches_reference()
     {
        // Verifies: REQ-0082
        // Reference computed using the RFC 3826 §2.1 algorithm H(auth_key || eid || auth_key),
        // validated against the RFC 3414 §A.3.1 MD5 and §A.3.2 SHA-1 test vectors:
        //   import hashlib
        //   auth_key = bytes([0xCD] * 64)
        //   engine_id = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        //   full_hash = hashlib.sha512(auth_key + engine_id + auth_key).digest()
        //   priv_key_aes256 = full_hash[:32]
        //   # => 05e43de2b7fc67e8b1fe1e28454d1e8bef33368e9c1021055ceb6d5a1dcef63d
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes256,
        );
        let expected: [u8; 32] = [
            0x05, 0xe4, 0x3d, 0xe2, 0xb7, 0xfc, 0x67, 0xe8, 0xb1, 0xfe, 0x1e, 0x28, 0x45, 0x4d,
            0x1e, 0x8b, 0xef, 0x33, 0x36, 0x8e, 0x9c, 0x10, 0x21, 0x05, 0x5c, 0xeb, 0x6d, 0x5a,
            0x1d, 0xce, 0xf6, 0x3d,
        ];
        assert_eq!(priv_key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_single_byte_password_when_derive_sha256_key_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using the RFC 3414 §2.6 algorithm H(Ku || eid || Ku),
        // validated against the RFC 3414 §A.3.1 MD5 and §A.3.2 SHA-1 test vectors:
        //   import hashlib
        //   pw = b"x"
        //   stream_len = 1048576
        //   full_copies = stream_len // len(pw)  # = 1048576
        //   remainder = stream_len % len(pw)     # = 0
        //   h = hashlib.sha256()
        //   for _ in range(full_copies): h.update(pw)
        //   # remainder is 0, no update needed
        //   ku = h.digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   kul = hashlib.sha256(ku + engine_id + ku).digest()
        //   # => 5c2925551d403cd57b64c5be56d6d1e3a612171ad6beb95fdca472ad88679651
        let key = password_to_localised_key(b"x", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let expected: [u8; 32] = [
            0x5c, 0x29, 0x25, 0x55, 0x1d, 0x40, 0x3c, 0xd5, 0x7b, 0x64, 0xc5, 0xbe, 0x56, 0xd6,
            0xd1, 0xe3, 0xa6, 0x12, 0x17, 0x1a, 0xd6, 0xbe, 0xb9, 0x5f, 0xdc, 0xa4, 0x72, 0xad,
            0x88, 0x67, 0x96, 0x51,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_password_longer_than_stream_when_derive_then_same_length_key() {
        // Verifies: REQ-0081
        let long_password = vec![0x42u8; 2_000_000]; // longer than 1 MiB
        let key =
            password_to_localised_key(&long_password, MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key.len(), 32);
    }
}
