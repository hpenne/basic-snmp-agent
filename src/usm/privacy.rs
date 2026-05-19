//! USM privacy protocols: AES-128-CFB128 and AES-256-CFB128.
//!
//! # Requirements
//! Implements: REQ-0083, REQ-0084, REQ-0088, REQ-0089

use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

use crate::usm::keys::SecretKey;

// ── PrivProtocol ──────────────────────────────────────────────────────────────

/// USM privacy protocol.
///
/// Determines the AES cipher variant used to encrypt and decrypt message
/// payloads, and the required localised key length.
///
/// # Requirements
/// Implements: REQ-0083, REQ-0084, REQ-0088, REQ-0089
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    /// `usmAesCfb128Protocol`: AES-128 in CFB128 mode, as defined in RFC 3826.
    ///
    /// Localised key length: 16 bytes. This is the mandatory-to-implement
    /// privacy protocol.
    Aes128,

    /// `usmAesCfb256Protocol`: AES-256 in CFB128 mode.
    ///
    /// Localised key length: 32 bytes.
    Aes256,
}

impl PrivProtocol {
    /// Return the required localised key length in bytes for this protocol.
    ///
    /// 16 bytes for [`Aes128`][PrivProtocol::Aes128],
    /// 32 bytes for [`Aes256`][PrivProtocol::Aes256].
    ///
    /// # Requirements
    /// Implements: REQ-0083, REQ-0084
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// Encrypt `plaintext` using AES-CFB128 with the given `key` and `iv`.
    ///
    /// Returns a ciphertext of the same length as `plaintext`, or an error if
    /// `key` does not have the correct length for this protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0088, REQ-0089
    ///
    /// # Errors
    ///
    /// Returns [`PrivError::InvalidKeyLength`] if the key length does not match
    /// the protocol's required length.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::privacy::PrivProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let key = SecretKey::new_from_exposed_slice(&[0x42_u8; 16]);
    /// let iv = [0x24_u8; 16];
    /// let ciphertext = PrivProtocol::Aes128.encrypt(&key, &iv, b"hello").unwrap();
    /// assert_eq!(ciphertext.len(), 5);
    /// ```
    pub fn encrypt(
        self,
        key: &SecretKey,
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PrivError> {
        if key.len() != self.key_len() {
            return Err(PrivError::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        let mut ciphertext = plaintext.to_vec();
        match self {
            Self::Aes128 => {
                // `new_from_slices` only fails if the key or IV lengths are
                // wrong; we have already validated key length above, and the
                // IV is a fixed-size [u8; 16] matching AES's block size.
                cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(key.as_bytes(), iv)
                    .map_err(|_| PrivError::CipherInitialisation)?
                    .encrypt(&mut ciphertext);
            }
            Self::Aes256 => {
                cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(key.as_bytes(), iv)
                    .map_err(|_| PrivError::CipherInitialisation)?
                    .encrypt(&mut ciphertext);
            }
        }
        Ok(ciphertext)
    }

    /// Decrypt `ciphertext` using AES-CFB128 with the given `key` and `iv`.
    ///
    /// Returns a plaintext of the same length as `ciphertext`, or an error if
    /// `key` does not have the correct length for this protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0088, REQ-0089
    ///
    /// # Errors
    ///
    /// Returns [`PrivError::InvalidKeyLength`] if the key length does not match
    /// the protocol's required length.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::privacy::PrivProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let key = SecretKey::new_from_exposed_slice(&[0x42_u8; 16]);
    /// let iv = [0x24_u8; 16];
    /// let ciphertext = PrivProtocol::Aes128.encrypt(&key, &iv, b"hello").unwrap();
    /// let recovered = PrivProtocol::Aes128.decrypt(&key, &iv, &ciphertext).unwrap();
    /// assert_eq!(recovered, b"hello");
    /// ```
    pub fn decrypt(
        self,
        key: &SecretKey,
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PrivError> {
        if key.len() != self.key_len() {
            return Err(PrivError::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }
        let mut plaintext = ciphertext.to_vec();
        match self {
            Self::Aes128 => {
                // `new_from_slices` only fails if the key or IV lengths are
                // wrong; we have already validated key length above, and the
                // IV is a fixed-size [u8; 16] matching AES's block size.
                cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(key.as_bytes(), iv)
                    .map_err(|_| PrivError::CipherInitialisation)?
                    .decrypt(&mut plaintext);
            }
            Self::Aes256 => {
                cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(key.as_bytes(), iv)
                    .map_err(|_| PrivError::CipherInitialisation)?
                    .decrypt(&mut plaintext);
            }
        }
        Ok(plaintext)
    }
}

// ── PrivError ─────────────────────────────────────────────────────────────────

/// Error type for privacy operations.
#[derive(Debug, PartialEq, Eq)]
pub enum PrivError {
    /// The supplied key has the wrong length for the privacy protocol.
    InvalidKeyLength { expected: usize, actual: usize },
    /// Internal error: cipher initialisation failed despite validated parameters.
    CipherInitialisation,
}

impl std::fmt::Display for PrivError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => write!(
                f,
                "invalid privacy key length: expected {expected} bytes, got {actual}"
            ),
            Self::CipherInitialisation => write!(f, "cipher initialisation failed"),
        }
    }
}

impl std::error::Error for PrivError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── key_len ───────────────────────────────────────────────────────────────

    #[test]
    fn aes128_key_len_is_16() {
        // Verifies: REQ-0083, REQ-0084
        assert_eq!(PrivProtocol::Aes128.key_len(), 16);
    }

    #[test]
    fn aes256_key_len_is_32() {
        // Verifies: REQ-0083, REQ-0084
        assert_eq!(PrivProtocol::Aes256.key_len(), 32);
    }

    // ── encrypt length ────────────────────────────────────────────────────────

    #[test]
    fn given_correct_key_when_encrypt_aes128_then_returns_same_length() {
        // Verifies: REQ-0088
        let key = SecretKey::new_from_exposed_slice(&[0x42_u8; 16]);
        let iv = [0x24_u8; 16];
        let ciphertext = PrivProtocol::Aes128
            .encrypt(&key, &iv, b"hello world")
            .unwrap();
        assert_eq!(ciphertext.len(), b"hello world".len());
        assert_ne!(ciphertext.as_slice(), b"hello world");
    }

    #[test]
    fn given_correct_key_when_encrypt_aes256_then_returns_same_length() {
        // Verifies: REQ-0089
        let key = SecretKey::new_from_exposed_slice(&[0x42_u8; 32]);
        let iv = [0x24_u8; 16];
        let ciphertext = PrivProtocol::Aes256
            .encrypt(&key, &iv, b"hello world")
            .unwrap();
        assert_eq!(ciphertext.len(), b"hello world".len());
        assert_ne!(ciphertext.as_slice(), b"hello world");
    }

    // ── encrypt error ─────────────────────────────────────────────────────────

    #[test]
    fn given_wrong_key_length_when_encrypt_aes128_then_error() {
        // Verifies: REQ-0084, REQ-0088
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]); // 32 bytes, not 16
        let iv = [0_u8; 16];
        let result = PrivProtocol::Aes128.encrypt(&key, &iv, b"data");
        assert_eq!(
            result,
            Err(PrivError::InvalidKeyLength {
                expected: 16,
                actual: 32
            })
        );
    }

    #[test]
    fn given_wrong_key_length_when_encrypt_aes256_then_error() {
        // Verifies: REQ-0084, REQ-0089
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 16]); // 16 bytes, not 32
        let iv = [0_u8; 16];
        let result = PrivProtocol::Aes256.encrypt(&key, &iv, b"data");
        assert_eq!(
            result,
            Err(PrivError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
    }

    // ── decrypt error ─────────────────────────────────────────────────────────

    #[test]
    fn given_wrong_key_length_when_decrypt_aes128_then_error() {
        // Verifies: REQ-0084, REQ-0088
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]); // 32 bytes, not 16
        let iv = [0_u8; 16];
        let result = PrivProtocol::Aes128.decrypt(&key, &iv, b"data");
        assert_eq!(
            result,
            Err(PrivError::InvalidKeyLength {
                expected: 16,
                actual: 32
            })
        );
    }

    #[test]
    fn given_wrong_key_length_when_decrypt_aes256_then_error() {
        // Verifies: REQ-0084, REQ-0089
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 16]); // 16 bytes, not 32
        let iv = [0_u8; 16];
        let result = PrivProtocol::Aes256.decrypt(&key, &iv, b"data");
        assert_eq!(
            result,
            Err(PrivError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
    }

    // ── roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn given_correct_key_when_roundtrip_aes128_then_recovers_plaintext() {
        // Verifies: REQ-0088
        let key = SecretKey::new_from_exposed_slice(&[0x11_u8; 16]);
        let iv = [0xFF_u8; 16];
        let original = b"SNMP privacy roundtrip test";
        let ciphertext = PrivProtocol::Aes128.encrypt(&key, &iv, original).unwrap();
        let recovered = PrivProtocol::Aes128
            .decrypt(&key, &iv, &ciphertext)
            .unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn given_correct_key_when_roundtrip_aes256_then_recovers_plaintext() {
        // Verifies: REQ-0089
        let key = SecretKey::new_from_exposed_slice(&[0x22_u8; 32]);
        let iv = [0xAA_u8; 16];
        let original = b"SNMP privacy roundtrip test AES-256";
        let ciphertext = PrivProtocol::Aes256.encrypt(&key, &iv, original).unwrap();
        let recovered = PrivProtocol::Aes256
            .decrypt(&key, &iv, &ciphertext)
            .unwrap();
        assert_eq!(recovered, original);
    }

    // ── empty input ───────────────────────────────────────────────────────────

    #[test]
    fn given_empty_plaintext_when_roundtrip_aes128_then_returns_empty() {
        // Verifies: REQ-0088
        let key = SecretKey::new_from_exposed_slice(&[0x42_u8; 16]);
        let iv = [0x24_u8; 16];
        let ciphertext = PrivProtocol::Aes128.encrypt(&key, &iv, b"").unwrap();
        assert!(ciphertext.is_empty());
        let recovered = PrivProtocol::Aes128
            .decrypt(&key, &iv, &ciphertext)
            .unwrap();
        assert!(recovered.is_empty());
    }

    // ── IV sensitivity ────────────────────────────────────────────────────────

    #[test]
    fn given_different_ivs_when_encrypt_same_plaintext_then_different_ciphertext() {
        // Verifies: REQ-0088 — IV is incorporated into the keystream
        let key = SecretKey::new_from_exposed_slice(&[0x33_u8; 16]);
        let iv_a = [0x00_u8; 16];
        let iv_b = [0x01_u8; 16];
        let plaintext = b"identical plaintext";
        let ct_a = PrivProtocol::Aes128
            .encrypt(&key, &iv_a, plaintext)
            .unwrap();
        let ct_b = PrivProtocol::Aes128
            .encrypt(&key, &iv_b, plaintext)
            .unwrap();
        assert_ne!(ct_a, ct_b);
    }

    // ── NIST reference vector ─────────────────────────────────────────────────

    #[test]
    fn given_known_inputs_when_encrypt_aes128_then_matches_reference_vector() {
        // Verifies: REQ-0088
        // NIST SP 800-38A, Section F.3.13: CFB128-AES128.Encrypt, Block #1.
        // Source: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        let key = SecretKey::new_from_exposed_slice(&[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ]);
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c,
            0xfb, 0x4a,
        ];
        let ciphertext = PrivProtocol::Aes128.encrypt(&key, &iv, &plaintext).unwrap();
        assert_eq!(ciphertext.as_slice(), expected_ciphertext.as_slice());
    }

    // ── error display ─────────────────────────────────────────────────────────

    #[test]
    fn priv_error_invalid_key_length_display() {
        let e = PrivError::InvalidKeyLength {
            expected: 16,
            actual: 32,
        };
        assert_eq!(
            e.to_string(),
            "invalid privacy key length: expected 16 bytes, got 32"
        );
    }

    #[test]
    fn priv_error_cipher_initialisation_display() {
        let e = PrivError::CipherInitialisation;
        assert_eq!(e.to_string(), "cipher initialisation failed");
    }

    #[test]
    fn priv_error_implements_std_error() {
        let e: &dyn std::error::Error = &PrivError::InvalidKeyLength {
            expected: 16,
            actual: 0,
        };
        assert!(e.source().is_none());
    }
}
