//! `MasterKey` — the first step in the key‑derivation pipeline.
//!
//! A `MasterKey` is a 32‑byte value derived from a password and email via
//! PBKDF2‑HMAC‑SHA256.  It can only be stretched into a `StretchedKeys`.

use std::num::NonZeroU32;

use anyhow::Result;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::stretched_keys::StretchedKeys;

// ── Insecure MAC override (process‑wide flag) ──────────────────────────────
//
// Set once at CLI startup from `--allow-insecure-mac`.  Checked by
// `CryptoKeys::decrypt()` when ciphertext lacks a MAC integrity tag.
// The env var `VAULTWARDEN_ALLOW_INSECURE_MAC` is also consulted as a
// fallback so that library consumers (and tests) can enable the bypass
// without the CLI flag.

static ALLOW_INSECURE_MAC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set the process‑wide `allow_insecure_mac` flag.
pub fn set_allow_insecure_mac(allow: bool) {
    ALLOW_INSECURE_MAC.store(allow, std::sync::atomic::Ordering::Relaxed);
}

/// Read the process‑wide `allow_insecure_mac` flag.
pub fn allow_insecure_mac() -> bool {
    ALLOW_INSECURE_MAC.load(std::sync::atomic::Ordering::Relaxed)
}
/// PBKDF2 iteration count that is guaranteed to be non‑zero.
///
/// Wraps [`NonZeroU32`] so that zero iterations (which would make the derived
/// key trivially crackable) is a compile‑/construction‑time error rather than
/// a runtime footgun.
///
/// # Construction
///
/// - [`KdfIterations::new(n)`] returns `None` when `n == 0`.
/// - [`KdfIterations::default()`] returns 600 000 (the Bitwarden standard).
/// - Deserialising `0` from JSON also fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KdfIterations(NonZeroU32);

impl KdfIterations {
    /// Create a `KdfIterations` from a raw `u32`, returning `None` if the
    /// value is `0`.
    #[must_use]
    pub fn new(iterations: u32) -> Option<Self> {
        NonZeroU32::new(iterations).map(Self)
    }

    /// Return the iteration count as a `u32`.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl Default for KdfIterations {
    /// The Bitwarden standard default — 600 000 iterations.
    fn default() -> Self {
        // Safety: 600_000 is statically known to be non-zero.
        Self(unsafe { NonZeroU32::new_unchecked(600_000) })
    }
}

impl From<KdfIterations> for u32 {
    fn from(kdf: KdfIterations) -> Self {
        kdf.get()
    }
}

/// A 32‑byte master key derived from the user's password and email.
///
/// This is the **first step** in the key‑derivation pipeline.  The only
/// way to obtain a `MasterKey` is via [`MasterKey::derive`].  To move
/// to the next pipeline stage call [`MasterKey::stretch`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MasterKey").field(&"[REDACTED]").finish()
    }
}

impl MasterKey {
    /// Derive the master key from password and email using PBKDF2‑HMAC‑SHA256.
    #[must_use]
    pub fn derive(password: &str, email: &str, iterations: KdfIterations) -> Self {
        let email_lower = email.to_lowercase();
        let mut bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            email_lower.as_bytes(),
            iterations.get(),
            &mut bytes,
        );
        Self(bytes)
    }

    /// Stretch this master key into encryption + MAC keys via HKDF‑Expand.
    ///
    /// Bitwarden uses HKDF‑Expand directly with the master key as PRK,
    /// skipping the HKDF‑Extract step.
    ///
    /// # Errors
    ///
    /// Returns an error if HKDF initialisation or key expansion fails.
    pub fn stretch(&self) -> Result<StretchedKeys> {
        StretchedKeys::from_master_key(&self.0)
    }

    /// Convenience: stretch and then decrypt the encrypted symmetric key
    /// in one call.
    ///
    /// # Errors
    ///
    /// Returns an error if stretching fails, or if the encrypted symmetric key
    /// cannot be decrypted.
    pub fn decrypt_symmetric_key(&self, encrypted_key: &str) -> Result<crate::crypto::CryptoKeys> {
        let stretched = self.stretch()?;
        stretched.decrypt_symmetric_key(encrypted_key)
    }

    /// Return the raw 32‑byte key material.
    ///
    /// Needed for serialization and testing.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Always returns 32 (compile‑time guarantee via the type).
    #[must_use]
    pub fn len(&self) -> usize {
        32
    }

    /// Returns `true` if the key is empty — always `false` for `MasterKey`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_derive_basic() {
        let key = MasterKey::derive(
            "password123",
            "test@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        assert_eq!(key.len(), 32);
        let key2 = MasterKey::derive(
            "password123",
            "test@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_email_case_insensitive() {
        let key_lower = MasterKey::derive(
            "password123",
            "test@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let key_upper = MasterKey::derive(
            "password123",
            "TEST@EXAMPLE.COM",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let key_mixed = MasterKey::derive(
            "password123",
            "Test@Example.Com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        assert_eq!(key_lower.as_bytes(), key_upper.as_bytes());
        assert_eq!(key_lower.as_bytes(), key_mixed.as_bytes());
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let k1 = MasterKey::derive(
            "password1",
            "user1@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let k2 = MasterKey::derive(
            "password2",
            "user1@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let k3 = MasterKey::derive(
            "password1",
            "user2@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        assert_ne!(k1.as_bytes(), k2.as_bytes());
        assert_ne!(k1.as_bytes(), k3.as_bytes());
    }

    #[test]
    fn test_different_iterations_different_outputs() {
        let k100k = MasterKey::derive(
            "password123",
            "test@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let k200k = MasterKey::derive(
            "password123",
            "test@example.com",
            KdfIterations::new(200_000).expect("non-zero iterations"),
        );
        assert_ne!(k100k.as_bytes(), k200k.as_bytes());
    }

    #[test]
    fn test_stretch_produces_stretched_keys() {
        let mk = MasterKey::derive(
            "p4ss",
            "user@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let stretched = mk.stretch().unwrap();
        let _ = stretched;
    }

    #[test]
    fn test_decrypt_symmetric_key_integration() {
        let mk = MasterKey::derive(
            "testpassword",
            "test@example.com",
            KdfIterations::new(100_000).expect("non-zero iterations"),
        );
        let symmetric_key: Vec<u8> = {
            let mut v = vec![0x42u8; 32];
            v.extend_from_slice(&[0x43u8; 32]);
            v
        };
        let stretched = mk.stretch().unwrap();
        let encrypted_key = crate::crypto::crypto_keys::tests::test_helpers::encrypt_bytes_for_test(
            &symmetric_key,
            stretched.enc_key(),
            stretched.mac_key(),
        );
        let keys = mk.decrypt_symmetric_key(&encrypted_key).unwrap();
        assert_eq!(keys.enc_key(), &[0x42u8; 32]);
        assert_eq!(keys.mac_key(), &[0x43u8; 32]);
    }
}
