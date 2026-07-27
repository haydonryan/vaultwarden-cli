//! RSA decryption operations (type 4 and 6).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

/// Decrypt an RSA‑OAEP encrypted value (type 4 or 6).
///
/// - Type 4 = RSA‑OAEP with SHA‑1
/// - Type 6 = RSA‑OAEP with SHA‑256
pub fn decrypt_rsa(encrypted: &str, private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let (enc_type, data) = encrypted
        .split_once('.')
        .context("Invalid encrypted string format")?;

    let enc_type: u8 = enc_type.parse().context("Invalid encryption type")?;

    let ciphertext = BASE64
        .decode(data)
        .context("Failed to decode RSA ciphertext")?;

    match enc_type {
        4 => private_key
            .decrypt(Oaep::<Sha1>::new(), &ciphertext)
            .map_err(|e| anyhow::anyhow!("RSA-OAEP decryption failed: {e}")),
        6 => private_key
            .decrypt(Oaep::<Sha256>::new(), &ciphertext)
            .map_err(|e| anyhow::anyhow!("RSA-OAEP decryption failed: {e}")),
        _ => anyhow::bail!("Unsupported RSA encryption type: {enc_type}"),
    }
}
