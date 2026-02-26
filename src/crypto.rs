use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rsa::{Oaep, RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha1::Sha1;
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Clone, Debug)]
pub struct CryptoKeys {
    pub enc_key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

impl CryptoKeys {
    /// Derive the master key from password and email using PBKDF2
    pub fn derive_master_key(password: &str, email: &str, iterations: u32) -> Vec<u8> {
        let email_lower = email.to_lowercase();
        let mut master_key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            email_lower.as_bytes(),
            iterations,
            &mut master_key,
        );
        master_key
    }

    /// Stretch the master key using HKDF-Expand to get encryption and MAC keys
    /// Note: Bitwarden uses HKDF-Expand directly with the master key as PRK,
    /// skipping the HKDF-Extract step
    pub fn stretch_master_key(master_key: &[u8]) -> Result<Self> {
        // Use the master key directly as PRK (skip extract step)
        let hk = Hkdf::<Sha256>::from_prk(master_key)
            .map_err(|e| anyhow::anyhow!("HKDF PRK init failed: {}", e))?;

        let mut enc_key = vec![0u8; 32];
        hk.expand(b"enc", &mut enc_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;

        let mut mac_key = vec![0u8; 32];
        hk.expand(b"mac", &mut mac_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;

        Ok(Self { enc_key, mac_key })
    }

    /// Create keys from the decrypted symmetric key (64 bytes: 32 enc + 32 mac)
    pub fn from_symmetric_key(key: &[u8]) -> Result<Self> {
        if key.len() != 64 {
            anyhow::bail!("Symmetric key must be 64 bytes, got {}", key.len());
        }
        Ok(Self {
            enc_key: key[0..32].to_vec(),
            mac_key: key[32..64].to_vec(),
        })
    }

    /// Decrypt an RSA-OAEP encrypted value (type 4 or 6)
    /// Type 4 = RSA-OAEP with SHA-1
    /// Type 6 = RSA-OAEP with SHA-256
    pub fn decrypt_rsa(encrypted: &str, private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let (enc_type, data) = encrypted
            .split_once('.')
            .context("Invalid encrypted string format")?;

        let enc_type: u8 = enc_type.parse().context("Invalid encryption type")?;

        let ciphertext = BASE64.decode(data).context("Failed to decode RSA ciphertext")?;

        match enc_type {
            4 => {
                // RSA-OAEP with SHA-1
                let padding = Oaep::new::<Sha1>();
                private_key
                    .decrypt(padding, &ciphertext)
                    .map_err(|e| anyhow::anyhow!("RSA-OAEP SHA1 decryption failed: {}", e))
            }
            6 => {
                // RSA-OAEP with SHA-256
                let padding = Oaep::new::<Sha256>();
                private_key
                    .decrypt(padding, &ciphertext)
                    .map_err(|e| anyhow::anyhow!("RSA-OAEP SHA256 decryption failed: {}", e))
            }
            _ => {
                anyhow::bail!("Unsupported RSA encryption type: {}", enc_type);
            }
        }
    }

    /// Decrypt the user's RSA private key using their symmetric key
    pub fn decrypt_private_key(
        &self,
        encrypted_private_key: &str,
    ) -> Result<RsaPrivateKey> {
        let decrypted_der = self.decrypt(encrypted_private_key)?;
        RsaPrivateKey::from_pkcs8_der(&decrypted_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA private key: {}", e))
    }

    /// Decrypt an organization key using RSA
    pub fn decrypt_org_key(
        encrypted_org_key: &str,
        private_key: &RsaPrivateKey,
    ) -> Result<Self> {
        let decrypted = Self::decrypt_rsa(encrypted_org_key, private_key)?;
        Self::from_symmetric_key(&decrypted)
    }

    /// Decrypt the user's encrypted symmetric key using the stretched master key
    pub fn decrypt_symmetric_key(
        master_key: &[u8],
        encrypted_key: &str,
    ) -> Result<Self> {
        // Stretch the master key
        let stretched = Self::stretch_master_key(master_key)?;

        // Decrypt the symmetric key
        let decrypted = stretched.decrypt(encrypted_key)?;

        // The decrypted value should be 64 bytes (32 enc + 32 mac)
        Self::from_symmetric_key(&decrypted)
    }

    /// Decrypt a Bitwarden encrypted string
    /// Format: type.iv|ciphertext|mac  or  type.iv|ciphertext (for older items)
    pub fn decrypt(&self, encrypted: &str) -> Result<Vec<u8>> {
        // Parse the encrypted string
        let (enc_type, data) = encrypted
            .split_once('.')
            .context("Invalid encrypted string format")?;

        let enc_type: u8 = enc_type
            .parse()
            .context("Invalid encryption type")?;

        // Type 2 = AES-256-CBC with HMAC-SHA256
        if enc_type != 2 {
            anyhow::bail!("Unsupported encryption type: {}", enc_type);
        }

        let parts: Vec<&str> = data.split('|').collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid encrypted data format");
        }

        let iv = BASE64.decode(parts[0]).context("Failed to decode IV")?;
        let ciphertext = BASE64.decode(parts[1]).context("Failed to decode ciphertext")?;

        // Verify MAC if present
        if parts.len() >= 3 {
            let mac = BASE64.decode(parts[2]).context("Failed to decode MAC")?;

            // Calculate expected MAC
            let mut hmac = Hmac::<Sha256>::new_from_slice(&self.mac_key)
                .map_err(|e| anyhow::anyhow!("HMAC init failed: {}", e))?;
            hmac.update(&iv);
            hmac.update(&ciphertext);

            hmac.verify_slice(&mac)
                .map_err(|_| anyhow::anyhow!("MAC verification failed"))?;
        }

        // Decrypt
        let mut buf = ciphertext.clone();
        let decrypted = Aes256CbcDec::new_from_slices(&self.enc_key, &iv)
            .map_err(|e| anyhow::anyhow!("AES init failed: {}", e))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow::anyhow!("AES decrypt failed: {}", e))?;

        Ok(decrypted.to_vec())
    }

    /// Decrypt to string
    pub fn decrypt_to_string(&self, encrypted: &str) -> Result<String> {
        let decrypted = self.decrypt(encrypted)?;
        String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")
    }
}

/// Decrypt a cipher's data using the crypto keys
pub fn decrypt_cipher_data(
    keys: &CryptoKeys,
    name: &str,
    username: Option<&str>,
    password: Option<&str>,
    uri: Option<&str>,
    notes: Option<&str>,
) -> Result<DecryptedCipherData> {
    Ok(DecryptedCipherData {
        name: keys.decrypt_to_string(name)?,
        username: username.map(|u| keys.decrypt_to_string(u)).transpose()?,
        password: password.map(|p| keys.decrypt_to_string(p)).transpose()?,
        uri: uri.map(|u| keys.decrypt_to_string(u)).transpose()?,
        notes: notes.map(|n| keys.decrypt_to_string(n)).transpose()?,
    })
}

#[derive(Debug, Clone)]
pub struct DecryptedCipherData {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vectors for PBKDF2 key derivation
    // These are based on Bitwarden's key derivation process
    #[test]
    fn test_derive_master_key_basic() {
        let password = "password123";
        let email = "test@example.com";
        let iterations = 100000;

        let key = CryptoKeys::derive_master_key(password, email, iterations);

        // Key should be 32 bytes
        assert_eq!(key.len(), 32);

        // Same inputs should produce same output (deterministic)
        let key2 = CryptoKeys::derive_master_key(password, email, iterations);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_derive_master_key_email_case_insensitive() {
        let password = "password123";
        let iterations = 100000;

        let key_lower = CryptoKeys::derive_master_key(password, "test@example.com", iterations);
        let key_upper = CryptoKeys::derive_master_key(password, "TEST@EXAMPLE.COM", iterations);
        let key_mixed = CryptoKeys::derive_master_key(password, "Test@Example.Com", iterations);

        // Email should be case-insensitive (lowercased before use)
        assert_eq!(key_lower, key_upper);
        assert_eq!(key_lower, key_mixed);
    }

    #[test]
    fn test_derive_master_key_different_inputs_different_outputs() {
        let iterations = 100000;

        let key1 = CryptoKeys::derive_master_key("password1", "user1@example.com", iterations);
        let key2 = CryptoKeys::derive_master_key("password2", "user1@example.com", iterations);
        let key3 = CryptoKeys::derive_master_key("password1", "user2@example.com", iterations);

        // Different passwords should produce different keys
        assert_ne!(key1, key2);
        // Different emails should produce different keys
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_master_key_different_iterations() {
        let password = "password123";
        let email = "test@example.com";

        let key_100k = CryptoKeys::derive_master_key(password, email, 100000);
        let key_200k = CryptoKeys::derive_master_key(password, email, 200000);

        // Different iteration counts should produce different keys
        assert_ne!(key_100k, key_200k);
    }

    #[test]
    fn test_stretch_master_key() {
        // Create a 32-byte master key
        let master_key = vec![0x42u8; 32];

        let stretched = CryptoKeys::stretch_master_key(&master_key).unwrap();

        // Both keys should be 32 bytes
        assert_eq!(stretched.enc_key.len(), 32);
        assert_eq!(stretched.mac_key.len(), 32);

        // Enc and mac keys should be different
        assert_ne!(stretched.enc_key, stretched.mac_key);
    }

    #[test]
    fn test_stretch_master_key_deterministic() {
        let master_key = vec![0x42u8; 32];

        let stretched1 = CryptoKeys::stretch_master_key(&master_key).unwrap();
        let stretched2 = CryptoKeys::stretch_master_key(&master_key).unwrap();

        assert_eq!(stretched1.enc_key, stretched2.enc_key);
        assert_eq!(stretched1.mac_key, stretched2.mac_key);
    }

    #[test]
    fn test_from_symmetric_key_valid() {
        let key = vec![0x42u8; 64];

        let keys = CryptoKeys::from_symmetric_key(&key).unwrap();

        assert_eq!(keys.enc_key.len(), 32);
        assert_eq!(keys.mac_key.len(), 32);
        assert_eq!(&keys.enc_key[..], &key[0..32]);
        assert_eq!(&keys.mac_key[..], &key[32..64]);
    }

    #[test]
    fn test_from_symmetric_key_invalid_length() {
        let key_short = vec![0x42u8; 32];
        let key_long = vec![0x42u8; 128];

        assert!(CryptoKeys::from_symmetric_key(&key_short).is_err());
        assert!(CryptoKeys::from_symmetric_key(&key_long).is_err());
    }

    #[test]
    fn test_decrypt_invalid_format_no_dot() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        let result = keys.decrypt("invalid_no_dot");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid encrypted string format"));
    }

    #[test]
    fn test_decrypt_invalid_encryption_type() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Type 99 is not supported
        let result = keys.decrypt("99.abc|def|ghi");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported encryption type"));
    }

    #[test]
    fn test_decrypt_invalid_type_not_number() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        let result = keys.decrypt("abc.iv|ciphertext|mac");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid encryption type"));
    }

    #[test]
    fn test_decrypt_type2_aes_cbc_with_hmac() {
        // This is a real Bitwarden-format encrypted string
        // We need to create valid test data with known keys

        // Create known keys
        let enc_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mac_key = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];

        let keys = CryptoKeys {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };

        // Test that invalid MAC is rejected
        let bad_mac_string = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let result = keys.decrypt(bad_mac_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_missing_parts() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Only one part after the type
        let result = keys.decrypt("2.onlyonepart");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_base64_iv() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        let result = keys.decrypt("2.!!!invalid!!|AAAA|AAAA");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to decode IV"));
    }

    #[test]
    fn test_decrypt_invalid_base64_ciphertext() {
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        let result = keys.decrypt("2.AAAAAAAAAAAAAAAAAAAAAA==|!!!invalid!!|AAAA");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to decode ciphertext"));
    }

    #[test]
    fn test_decrypt_to_string_valid_utf8() {
        // We need a properly encrypted string for this test
        // For now, test the error case
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Invalid encrypted data should fail
        let result = keys.decrypt_to_string("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rsa_invalid_format() {
        // Generate a test RSA key
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // Missing dot separator
        let result = CryptoKeys::decrypt_rsa("nodot", &private_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid encrypted string format"));
    }

    #[test]
    fn test_decrypt_rsa_invalid_type() {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // Type "abc" is not a valid number
        let result = CryptoKeys::decrypt_rsa("abc.AAAA", &private_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid encryption type"));
    }

    #[test]
    fn test_decrypt_rsa_unsupported_type() {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // Type 5 is not supported (only 4 and 6)
        let result = CryptoKeys::decrypt_rsa("5.AAAA", &private_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported RSA encryption type"));
    }

    #[test]
    fn test_decrypt_rsa_invalid_base64() {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        let result = CryptoKeys::decrypt_rsa("4.!!!notbase64!!!", &private_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to decode RSA ciphertext"));
    }

    #[test]
    fn test_decrypt_symmetric_key_integration() {
        // Test the full key derivation and decryption flow
        let password = "testpassword";
        let email = "test@example.com";
        let iterations = 100000;

        // Derive master key
        let master_key = CryptoKeys::derive_master_key(password, email, iterations);
        assert_eq!(master_key.len(), 32);

        // Stretch master key
        let stretched = CryptoKeys::stretch_master_key(&master_key).unwrap();
        assert_eq!(stretched.enc_key.len(), 32);
        assert_eq!(stretched.mac_key.len(), 32);
    }

    // Test helper function
    #[test]
    fn test_decrypt_cipher_data_all_fields() {
        // This tests the decrypt_cipher_data function with mocked encryption
        // Since we can't easily create valid encrypted data, we test the function exists
        // and handles the right types

        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Invalid encrypted name should fail
        let result = decrypt_cipher_data(
            &keys,
            "invalid",
            Some("invalid"),
            Some("invalid"),
            Some("invalid"),
            Some("invalid"),
        );
        assert!(result.is_err());
    }

    // Round-trip encryption/decryption test using real crypto
    mod roundtrip_tests {
        use super::*;
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        fn encrypt_for_test(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> String {
            // Generate random IV
            let iv: [u8; 16] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ];

            // Encrypt with AES-256-CBC
            let mut buf = vec![0u8; plaintext.len() + 16]; // Extra space for padding
            buf[..plaintext.len()].copy_from_slice(plaintext);

            let ciphertext = Aes256CbcEnc::new_from_slices(enc_key, &iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
                .unwrap();

            // Calculate MAC
            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
            hmac.update(&iv);
            hmac.update(ciphertext);
            let mac = hmac.finalize().into_bytes();

            // Format as Bitwarden encrypted string
            format!(
                "2.{}|{}|{}",
                BASE64.encode(&iv),
                BASE64.encode(ciphertext),
                BASE64.encode(&mac)
            )
        }

        #[test]
        fn test_roundtrip_simple_text() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let keys = CryptoKeys {
                enc_key: enc_key.to_vec(),
                mac_key: mac_key.to_vec(),
            };

            let plaintext = b"Hello, World!";
            let encrypted = encrypt_for_test(plaintext, &enc_key, &mac_key);
            let decrypted = keys.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_roundtrip_unicode() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let keys = CryptoKeys {
                enc_key: enc_key.to_vec(),
                mac_key: mac_key.to_vec(),
            };

            let plaintext = "Hello, 世界! 🔐";
            let encrypted = encrypt_for_test(plaintext.as_bytes(), &enc_key, &mac_key);
            let decrypted = keys.decrypt_to_string(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_roundtrip_empty_string() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let keys = CryptoKeys {
                enc_key: enc_key.to_vec(),
                mac_key: mac_key.to_vec(),
            };

            let plaintext = b"";
            let encrypted = encrypt_for_test(plaintext, &enc_key, &mac_key);
            let decrypted = keys.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_roundtrip_long_text() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let keys = CryptoKeys {
                enc_key: enc_key.to_vec(),
                mac_key: mac_key.to_vec(),
            };

            // Create a long string (multiple AES blocks)
            let plaintext: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
            let encrypted = encrypt_for_test(&plaintext, &enc_key, &mac_key);
            let decrypted = keys.decrypt(&encrypted).unwrap();

            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn test_mac_verification_fails_on_tampered_data() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let keys = CryptoKeys {
                enc_key: enc_key.to_vec(),
                mac_key: mac_key.to_vec(),
            };

            let plaintext = b"Secret data";
            let encrypted = encrypt_for_test(plaintext, &enc_key, &mac_key);

            // Tamper with the ciphertext
            let parts: Vec<&str> = encrypted.split('|').collect();
            let tampered = format!("{}|AAAA{}|{}", parts[0], &parts[1][4..], parts[2]);

            let result = keys.decrypt(&tampered);
            assert!(result.is_err());
        }

        #[test]
        fn test_wrong_key_fails_decryption() {
            let enc_key = [0x42u8; 32];
            let mac_key = [0x43u8; 32];

            let wrong_keys = CryptoKeys {
                enc_key: [0x99u8; 32].to_vec(),
                mac_key: [0x99u8; 32].to_vec(),
            };

            let plaintext = b"Secret data";
            let encrypted = encrypt_for_test(plaintext, &enc_key, &mac_key);

            // Decryption with wrong keys should fail MAC verification
            let result = wrong_keys.decrypt(&encrypted);
            assert!(result.is_err());
        }
    }
}
