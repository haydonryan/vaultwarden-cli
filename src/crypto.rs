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
