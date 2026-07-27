//! Typestate-guided key derivation pipeline.
//!
//! The key derivation follows a strict linear pipeline:
//!
//!   `MasterKey` → `StretchedKeys` → `CryptoKeys` → (decrypt / `RsaPrivateKey`)
//!
//! Each step produces a new type, and wrong-order calls are compile errors.
//! - `MasterKey` is the 32‑byte PBKDF2‑derived key from password + email.
//! - `StretchedKeys` is the HKDF‑expanded encryption + MAC key pair.
//! - `CryptoKeys` is the decrypted 64‑byte symmetric key (32 enc + 32 mac).
//! - `RsaPrivateKey` can be obtained from `CryptoKeys::decrypt_private_key`.
//! - Org keys can be decrypted from `RsaPrivateKey` back into `CryptoKeys`.

pub(crate) mod master_key;
pub(crate) mod stretched_keys;
pub(crate) mod crypto_keys;
pub(crate) mod rsa_ops;

pub use master_key::MasterKey;
pub use master_key::set_allow_insecure_mac;
pub use master_key::allow_insecure_mac;
pub use stretched_keys::StretchedKeys;
pub use crypto_keys::CryptoKeys;
pub use rsa_ops::decrypt_rsa;
