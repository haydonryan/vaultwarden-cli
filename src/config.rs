use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::crypto::CryptoKeys;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: Option<String>,
    pub client_id: Option<String>,
    pub email: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expiry: Option<i64>,
    pub encrypted_key: Option<String>,
    pub kdf_iterations: Option<u32>,
    // Store derived keys (base64 encoded) - only in memory/session
    #[serde(skip)]
    pub crypto_keys: Option<CryptoKeys>,
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        ProjectDirs::from("com", "vaultwarden", "vaultwarden-cli")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .context("Failed to determine config directory")
    }

    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.json"))
    }

    pub fn keys_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("keys.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config from {:?}", path))?;
            let mut config: Config = serde_json::from_str(&content).context("Failed to parse config")?;

            // Try to load saved keys
            config.load_saved_keys().ok();

            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {:?}", parent))?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config to {:?}", path))?;
        Ok(())
    }

    pub fn save_keys(&self) -> Result<()> {
        if let Some(keys) = &self.crypto_keys {
            let path = Self::keys_path()?;
            let keys_data = SavedKeys {
                enc_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.enc_key),
                mac_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.mac_key),
            };
            let content = serde_json::to_string(&keys_data)?;
            fs::write(&path, content)?;
        }
        Ok(())
    }

    pub fn load_saved_keys(&mut self) -> Result<()> {
        let path = Self::keys_path()?;
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let keys_data: SavedKeys = serde_json::from_str(&content)?;
            let enc_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.enc_key)?;
            let mac_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.mac_key)?;
            self.crypto_keys = Some(CryptoKeys {
                enc_key,
                mac_key,
            });
        }
        Ok(())
    }

    pub fn delete_saved_keys(&self) -> Result<()> {
        let path = Self::keys_path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        self.access_token = None;
        self.refresh_token = None;
        self.token_expiry = None;
        self.crypto_keys = None;
        self.encrypted_key = None;
        self.delete_saved_keys()?;
        self.save()
    }

    pub fn is_logged_in(&self) -> bool {
        self.access_token.is_some() && self.server.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.crypto_keys.is_some()
    }

    pub fn get_server(&self) -> Option<&str> {
        self.server.as_deref()
    }
}

#[derive(Serialize, Deserialize)]
struct SavedKeys {
    enc_key: String,
    mac_key: String,
}

// Store client secret securely using keyring
pub fn store_client_secret(client_id: &str, secret: &str) -> Result<()> {
    let entry = keyring::Entry::new("vaultwarden-cli", client_id)?;
    entry.set_password(secret)?;
    Ok(())
}

pub fn get_client_secret(client_id: &str) -> Result<String> {
    let entry = keyring::Entry::new("vaultwarden-cli", client_id)?;
    entry.get_password().context("Client secret not found")
}

pub fn delete_client_secret(client_id: &str) -> Result<()> {
    let entry = keyring::Entry::new("vaultwarden-cli", client_id)?;
    entry.delete_password().ok(); // Ignore errors if not found
    Ok(())
}
