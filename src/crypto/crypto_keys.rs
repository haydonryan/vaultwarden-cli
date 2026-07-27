//! `CryptoKeys` — the final symmetric‑key type in the derivation pipeline.
//!
//! A `CryptoKeys` holds 32 bytes of encryption key and 32 bytes of MAC key.
//! It can only be obtained through one of two paths:
//!
//! 1. `StretchedKeys::decrypt_symmetric_key` (the normal login flow).
//! 2. `CryptoKeys::decrypt_org_key` via an `RsaPrivateKey` (org key flow).
//!
//! Once obtained, callers can decrypt data or decrypt their RSA private key.

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, KeyInit, Mac};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::master_key::allow_insecure_mac;
use crate::crypto::rsa_ops;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The symmetric encryption + MAC key pair used for vault data decryption.
///
/// This is the **third step** in the derivation pipeline.  Instances can
/// only be created through the proper pipeline transitions — never by
/// directly specifying key bytes in application code.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CryptoKeys {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl std::fmt::Debug for CryptoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoKeys")
            .field("enc_key", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .finish()
    }
}

impl CryptoKeys {
    // ── Pipeline constructors (the only ways to obtain CryptoKeys) ──────

    /// Internal: create `CryptoKeys` from a validated 64‑byte symmetric key.
    pub(crate) fn from_symmetric_key(key: &[u8]) -> Result<Self> {
        if key.len() != 64 {
            anyhow::bail!("Symmetric key must be 64 bytes, got {}", key.len());
        }
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&key[0..32]);
        mac_key.copy_from_slice(&key[32..64]);
        Ok(Self { enc_key, mac_key })
    }

    /// Construct `CryptoKeys` from raw key bytes (for config deserialisation).
    pub fn from_key_bytes(enc_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { enc_key, mac_key }
    }

    /// Decrypt an organisation key using an RSA private key.
    pub fn decrypt_org_key(encrypted_org_key: &str, private_key: &RsaPrivateKey) -> Result<Self> {
        let decrypted = rsa_ops::decrypt_rsa(encrypted_org_key, private_key)?;
        Self::from_symmetric_key(&decrypted)
    }

    // ── Decryption operations ───────────────────────────────────────────

    /// Decrypt the user's RSA private key using this symmetric key.
    pub fn decrypt_private_key(&self, encrypted_private_key: &str) -> Result<RsaPrivateKey> {
        let decrypted_der = self.decrypt(encrypted_private_key)?;
        RsaPrivateKey::from_pkcs8_der(&decrypted_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA private key: {e}"))
    }

    /// Decrypt a Bitwarden encrypted string.
    ///
    /// Format: `type.iv|ciphertext|mac` or `type.iv|ciphertext` (older items).
    pub fn decrypt(&self, encrypted: &str) -> Result<Vec<u8>> {
        Self::decrypt_with_keys(&self.enc_key, &self.mac_key, encrypted)
    }

    /// Decrypt to a UTF‑8 string.
    pub fn decrypt_to_string(&self, encrypted: &str) -> Result<String> {
        let decrypted = self.decrypt(encrypted)?;
        String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")
    }

    // ── Public accessors for serialization / config ──────────────────────

    /// Read the 32‑byte encryption key.
    pub fn enc_key_bytes(&self) -> &[u8; 32] {
        &self.enc_key
    }

    /// Read the 32‑byte MAC key.
    pub fn mac_key_bytes(&self) -> &[u8; 32] {
        &self.mac_key
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Core AES‑256‑CBC + HMAC‑SHA256 decryption logic.
    pub(crate) fn decrypt_with_keys(
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        encrypted: &str,
    ) -> Result<Vec<u8>> {
        let (enc_type, data) = encrypted
            .split_once('.')
            .context("Invalid encrypted string format")?;

        let enc_type: u8 = enc_type.parse().context("Invalid encryption type")?;

        if enc_type != 2 {
            anyhow::bail!("Unsupported encryption type: {enc_type}");
        }

        let parts: Vec<&str> = data.split('|').collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid encrypted data format");
        }

        let iv = BASE64.decode(parts[0]).context("Failed to decode IV")?;
        let ciphertext = BASE64
            .decode(parts[1])
            .context("Failed to decode ciphertext")?;

        // Verify MAC — reject ciphertext that lacks integrity protection
        if parts.len() < 3 {
            let allow = allow_insecure_mac()
                || std::env::var("VAULTWARDEN_ALLOW_INSECURE_MAC")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            if !allow {
                anyhow::bail!(
                    "Encrypted string is missing MAC (integrity tag). \
                     Refusing to decrypt unauthenticated ciphertext.\n\
                     To permit this, use --allow-insecure-mac or set VAULTWARDEN_ALLOW_INSECURE_MAC=1."
                );
            }
            eprintln!(
                "Warning: Decrypting ciphertext without MAC integrity verification. Data authenticity cannot be confirmed."
            );
        } else {
            let mac = BASE64.decode(parts[2]).context("Failed to decode MAC")?;

            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_slice())
                .map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
            hmac.update(&iv);
            hmac.update(&ciphertext);

            hmac.verify_slice(&mac)
                .map_err(|err| anyhow::anyhow!("MAC verification failed: {err}"))?;
        }

        let mut buf = ciphertext;
        let decrypted = Aes256CbcDec::new_from_slices(enc_key.as_slice(), &iv)
            .map_err(|e| anyhow::anyhow!("AES init failed: {e}"))?
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow::anyhow!("AES decrypt failed: {e}"))?;

        Ok(decrypted.to_vec())
    }

    /// Expose enc_key for tests.
    #[cfg(test)]
    pub(crate) fn enc_key(&self) -> &[u8; 32] {
        &self.enc_key
    }

    /// Expose mac_key for tests.
    #[cfg(test)]
    pub(crate) fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::MasterKey;

    #[test]
    fn test_from_symmetric_key_valid() {
        let key = [0x42u8; 64];
        let keys = CryptoKeys::from_symmetric_key(&key).unwrap();
        assert_eq!(keys.enc_key(), &[0x42u8; 32]);
        assert_eq!(keys.mac_key(), &[0x42u8; 32]);
    }

    #[test]
    fn test_from_symmetric_key_invalid_length() {
        assert!(CryptoKeys::from_symmetric_key(&[0x42u8; 32]).is_err());
        assert!(CryptoKeys::from_symmetric_key(&[0x42u8; 128]).is_err());
    }

    #[test]
    fn test_decrypt_invalid_format_no_dot() {
        let mk = MasterKey::derive("p4ss", "user@example.com", 100_000);
        let sym_key = vec![0x42u8; 64];
        let enc_key_v = test_helpers::encrypt_bytes_for_test(
            &sym_key,
            mk.stretch().unwrap().enc_key(),
            mk.stretch().unwrap().mac_key(),
        );
        let keys = mk
            .stretch()
            .unwrap()
            .decrypt_symmetric_key(&enc_key_v)
            .unwrap();

        let result = keys.decrypt("invalid_no_dot");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid encrypted string format")
        );
    }

    #[test]
    fn test_decrypt_invalid_encryption_type() {
        let mk = MasterKey::derive("p4ss", "user@example.com", 100_000);
        let sym_key = vec![0x42u8; 64];
        let enc_key_v = test_helpers::encrypt_bytes_for_test(
            &sym_key,
            mk.stretch().unwrap().enc_key(),
            mk.stretch().unwrap().mac_key(),
        );
        let keys = mk
            .stretch()
            .unwrap()
            .decrypt_symmetric_key(&enc_key_v)
            .unwrap();

        let result = keys.decrypt("99.abc|def|ghi");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported encryption type")
        );
    }

    #[test]
    fn test_decrypt_invalid_type_not_number() {
        let mk = MasterKey::derive("p4ss", "user@example.com", 100_000);
        let sym_key = vec![0x42u8; 64];
        let enc_key_v = test_helpers::encrypt_bytes_for_test(
            &sym_key,
            mk.stretch().unwrap().enc_key(),
            mk.stretch().unwrap().mac_key(),
        );
        let keys = mk
            .stretch()
            .unwrap()
            .decrypt_symmetric_key(&enc_key_v)
            .unwrap();

        let result = keys.decrypt("abc.iv|ciphertext|mac");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid encryption type")
        );
    }

    #[test]
    fn test_decrypt_type2_aes_cbc_with_hmac() {
        let enc_key = [0x00u8; 32];
        let mac_key = [0x20u8; 32];

        let bad_mac_string = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let result = CryptoKeys::decrypt_with_keys(&enc_key, &mac_key, bad_mac_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_missing_parts() {
        let enc_key = [0x00u8; 32];
        let mac_key = [0x20u8; 32];
        let result = CryptoKeys::decrypt_with_keys(&enc_key, &mac_key, "2.onlyonepart");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_base64_iv() {
        let enc_key = [0x00u8; 32];
        let mac_key = [0x20u8; 32];
        let result = CryptoKeys::decrypt_with_keys(&enc_key, &mac_key, "2.!!!invalid!!|AAAA|AAAA");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to decode IV")
        );
    }

    #[test]
    fn test_decrypt_invalid_base64_ciphertext() {
        let enc_key = [0x00u8; 32];
        let mac_key = [0x20u8; 32];
        let result = CryptoKeys::decrypt_with_keys(
            &enc_key,
            &mac_key,
            "2.AAAAAAAAAAAAAAAAAAAAAA==|!!!invalid!!|AAAA",
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to decode ciphertext")
        );
    }

    #[test]
    fn test_decrypt_to_string_invalid() {
        let mk = MasterKey::derive("p4ss", "user@example.com", 100_000);
        let sym_key = vec![0x42u8; 64];
        let enc_key_v = test_helpers::encrypt_bytes_for_test(
            &sym_key,
            mk.stretch().unwrap().enc_key(),
            mk.stretch().unwrap().mac_key(),
        );
        let keys = mk
            .stretch()
            .unwrap()
            .decrypt_symmetric_key(&enc_key_v)
            .unwrap();

        let result = keys.decrypt_to_string("invalid");
        assert!(result.is_err());
    }

    /// Test helpers that mirror the original `test_helpers` module.
    pub(crate) mod test_helpers {
        use super::*;
        use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        pub fn encrypt_bytes_for_test(
            plaintext: &[u8],
            enc_key: &[u8; 32],
            mac_key: &[u8; 32],
        ) -> String {
            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = plaintext.to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(enc_key.as_slice(), &iv)
                .unwrap()
                .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
                .unwrap()
                .to_vec();

            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_slice()).unwrap();
            hmac.update(&iv);
            hmac.update(&ciphertext);
            let mac = hmac.finalize().into_bytes();

            format!(
                "2.{}|{}|{}",
                BASE64.encode(&iv),
                BASE64.encode(&ciphertext),
                BASE64.encode(mac)
            )
        }
    }

    // ── Round-trip tests ──────────────────────────────────────────────────
    mod roundtrip_tests {
        use super::test_helpers::encrypt_bytes_for_test;
        use super::*;
        use crate::crypto::MasterKey;

        fn make_keys() -> (CryptoKeys, [u8; 32], [u8; 32]) {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];
            let sym_key: Vec<u8> = {
                let mut v = enc_key.to_vec();
                v.extend_from_slice(&mac_key);
                v
            };
            let mk = MasterKey::derive("testpw", "test@example.com", 100_000);
            let stretched = mk.stretch().unwrap();
            let encrypted =
                encrypt_bytes_for_test(&sym_key, stretched.enc_key(), stretched.mac_key());
            let keys = mk
                .stretch()
                .unwrap()
                .decrypt_symmetric_key(&encrypted)
                .unwrap();
            (keys, enc_key, mac_key)
        }

        #[test]
        fn test_roundtrip_simple_text() {
            let (keys, _, _) = make_keys();
            let plaintext = b"Hello, World!";
            let encrypted = encrypt_bytes_for_test(plaintext, keys.enc_key(), keys.mac_key());
            let decrypted = keys.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_roundtrip_unicode() {
            let (keys, _, _) = make_keys();
            let plaintext = "Hello, 世界! 🔐";
            let encrypted =
                encrypt_bytes_for_test(plaintext.as_bytes(), keys.enc_key(), keys.mac_key());
            let decrypted = keys.decrypt_to_string(&encrypted).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_roundtrip_empty_string() {
            let (keys, _, _) = make_keys();
            let encrypted = encrypt_bytes_for_test(b"", keys.enc_key(), keys.mac_key());
            let decrypted = keys.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, b"");
        }

        #[test]
        fn test_roundtrip_long_text() {
            let (keys, _, _) = make_keys();
            let plaintext: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
            let encrypted = encrypt_bytes_for_test(&plaintext, keys.enc_key(), keys.mac_key());
            let decrypted = keys.decrypt(&encrypted).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_mac_verification_fails_on_tampered_data() {
            let (keys, _, _) = make_keys();
            let plaintext = b"Secret data";
            let encrypted = encrypt_bytes_for_test(plaintext, keys.enc_key(), keys.mac_key());

            let parts: Vec<&str> = encrypted.split('|').collect();
            let tampered = format!("{}|AAAA{}|{}", parts[0], &parts[1][4..], parts[2]);
            let result = keys.decrypt(&tampered);
            assert!(result.is_err());
        }

        #[test]
        fn test_wrong_key_fails_decryption() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let plaintext = b"Secret data";
            let encrypted = encrypt_bytes_for_test(plaintext, &enc_key, &mac_key);

            let mk = MasterKey::derive("otherpw", "other@example.com", 100_000);
            let stretched = mk.stretch().unwrap();
            let sym_key: Vec<u8> = {
                let mut v = [0x99u8; 32].to_vec();
                v.extend_from_slice(&[0x99u8; 32]);
                v
            };
            let enc_sym =
                encrypt_bytes_for_test(&sym_key, stretched.enc_key(), stretched.mac_key());
            let wrong_keys = mk
                .stretch()
                .unwrap()
                .decrypt_symmetric_key(&enc_sym)
                .unwrap();

            let result = wrong_keys.decrypt(&encrypted);
            assert!(result.is_err());
        }
    }

    // ── RSA round-trip tests ──────────────────────────────────────────────
    mod rsa_roundtrip_tests {
        use super::test_helpers::encrypt_bytes_for_test;
        use super::*;
        use crate::crypto::{MasterKey, decrypt_rsa};
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
        use sha1::Sha1;
        use sha2::Sha256;

        #[test]
        fn test_decrypt_rsa_type4_success() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);

            let plaintext = b"secret data";
            let padding = Oaep::<Sha1>::new();
            let encrypted = public_key.encrypt(&mut rng, padding, plaintext).unwrap();
            let encrypted_str = format!("4.{}", BASE64.encode(&encrypted));

            let decrypted = decrypt_rsa(&encrypted_str, &private_key).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_decrypt_rsa_type6_success() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);

            let plaintext = b"secret data";
            let padding = Oaep::<Sha256>::new();
            let encrypted = public_key.encrypt(&mut rng, padding, plaintext).unwrap();
            let encrypted_str = format!("6.{}", BASE64.encode(&encrypted));

            let decrypted = decrypt_rsa(&encrypted_str, &private_key).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_decrypt_rsa_invalid_format() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            let result = decrypt_rsa("nodot", &private_key);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid encrypted string format")
            );
        }

        #[test]
        fn test_decrypt_rsa_invalid_type() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            let result = decrypt_rsa("abc.AAAA", &private_key);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid encryption type")
            );
        }

        #[test]
        fn test_decrypt_rsa_unsupported_type() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            let result = decrypt_rsa("5.AAAA", &private_key);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Unsupported RSA encryption type")
            );
        }

        #[test]
        fn test_decrypt_rsa_invalid_base64() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

            let result = decrypt_rsa("4.!!!notbase64!!!", &private_key);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Failed to decode RSA ciphertext")
            );
        }

        #[test]
        fn test_decrypt_private_key_success() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let der = private_key.to_pkcs8_der().unwrap().as_bytes().to_vec();

            let mk = MasterKey::derive("testpw", "test@example.com", 100_000);
            let stretched = mk.stretch().unwrap();
            let sym_key: Vec<u8> = {
                let mut v = vec![0x42u8; 32];
                v.extend_from_slice(&[0x43u8; 32]);
                v
            };
            let enc_sym = crate::crypto::crypto_keys::tests::test_helpers::encrypt_bytes_for_test(
                &sym_key,
                stretched.enc_key(),
                stretched.mac_key(),
            );
            let keys = mk
                .stretch()
                .unwrap()
                .decrypt_symmetric_key(&enc_sym)
                .unwrap();

            let encrypted = crate::crypto::crypto_keys::tests::test_helpers::encrypt_bytes_for_test(
                &der,
                keys.enc_key(),
                keys.mac_key(),
            );
            let decrypted_key = keys.decrypt_private_key(&encrypted).unwrap();

            let _ = decrypted_key.to_pkcs8_der().unwrap();
        }

        #[test]
        fn test_decrypt_org_key_success() {
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);

            let org_plaintext: Vec<u8> = (0..64).collect();
            let padding = Oaep::<Sha256>::new();
            let encrypted = public_key
                .encrypt(&mut rng, padding, &org_plaintext)
                .unwrap();
            let encrypted_str = format!("6.{}", BASE64.encode(&encrypted));

            let org_keys = CryptoKeys::decrypt_org_key(&encrypted_str, &private_key).unwrap();
            assert_eq!(org_keys.enc_key(), &org_plaintext[0..32]);
            assert_eq!(org_keys.mac_key(), &org_plaintext[32..64]);
        }
    }
}
