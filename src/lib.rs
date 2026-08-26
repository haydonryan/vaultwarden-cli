//! vaultwarden-cli library
//!
//! This library provides the core functionality for the vaultwarden-cli tool.
#![allow(clippy::pedantic, clippy::nursery)]

pub mod api;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod models;
mod totp;

pub fn install_rustls_crypto_provider() {
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) | Err(_) => {}
    }
}

#[cfg(test)]
pub(crate) static KEYRING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
