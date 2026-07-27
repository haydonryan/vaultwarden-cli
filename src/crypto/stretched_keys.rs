//! `StretchedKeys` — the second step in the key‑derivation pipeline.
//!
//! A `StretchedKeys` holds the 32‑byte encryption key and 32‑byte MAC key
//! produced by HKDF‑expanding a `MasterKey`.  It can only be obtained from
//! [`MasterKey::stretch`] (internal constructor) and provides the
//! [`StretchedKeys::decrypt_symmetric_key`] method to move to the next stage.

use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::crypto_keys::CryptoKeys;

/// The encryption and MAC keys produced by stretching a [`MasterKey`].
///
/// This is the **second step** in the pipeline.  The only way to obtain
/// a `StretchedKeys` is via [`MasterKey::stretch`].  To move to the next
/// stage call [`StretchedKeys::decrypt_symmetric_key`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StretchedKeys {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl std::fmt::Debug for StretchedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StretchedKeys")
            .field("enc_key", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .finish()
    }
}

impl StretchedKeys {
    /// Create `StretchedKeys` from a `MasterKey` via HKDF‑Expand.
    ///
    /// This is the **only** constructor — callers must go through
    /// `MasterKey::stretch()`.
    pub(crate) fn from_master_key(master_key_bytes: &[u8; 32]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::from_prk(master_key_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("HKDF PRK init failed: {e}"))?;

        let mut enc_key = [0u8; 32];
        hk.expand(b"enc", &mut enc_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand (enc) failed: {e}"))?;

        let mut mac_key = [0u8; 32];
        hk.expand(b"mac", &mut mac_key)
            .map_err(|e| anyhow::anyhow!("HKDF expand (mac) failed: {e}"))?;

        Ok(Self { enc_key, mac_key })
    }

    /// Decrypt the user's encrypted symmetric key to obtain [`CryptoKeys`].
    ///
    /// This is the only way to produce `CryptoKeys` from the stretch path.
    pub fn decrypt_symmetric_key(&self, encrypted_key: &str) -> Result<CryptoKeys> {
        let decrypted = CryptoKeys::decrypt_with_keys(&self.enc_key, &self.mac_key, encrypted_key)?;
        CryptoKeys::from_symmetric_key(&decrypted)
    }

    /// Read the 32‑byte encryption key (for serialization / testing).
    pub fn enc_key(&self) -> &[u8; 32] {
        &self.enc_key
    }

    /// Read the 32‑byte MAC key (for serialization / testing).
    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────
#[cfg(test)]
pub(crate) mod tests {
    use crate::crypto::{KdfIterations, MasterKey};

    #[test]
    fn test_stretch_deterministic() {
        let mk = MasterKey::derive(
            "p4ss",
            "user@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let s1 = mk.stretch().unwrap();
        let s2 = mk.stretch().unwrap();
        assert_eq!(s1.enc_key, s2.enc_key);
        assert_eq!(s1.mac_key, s2.mac_key);
    }

    #[test]
    fn test_enc_and_mac_keys_are_different() {
        let mk = MasterKey::derive(
            "p4ss",
            "user@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let s = mk.stretch().unwrap();
        assert_ne!(&s.enc_key[..], &s.mac_key[..]);
    }

    #[test]
    fn test_keys_are_32_bytes() {
        let mk = MasterKey::derive(
            "p4ss",
            "user@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let s = mk.stretch().unwrap();
        assert_eq!(s.enc_key.len(), 32);
        assert_eq!(s.mac_key.len(), 32);
    }
}
