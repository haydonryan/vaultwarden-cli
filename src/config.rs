use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub encrypted_private_key: Option<String>,
    pub kdf_iterations: Option<u32>,
    // Organization encrypted keys: org_id -> encrypted_key
    #[serde(default)]
    pub org_keys: HashMap<String, String>,
    // Store derived keys (base64 encoded) - only in memory/session
    #[serde(skip)]
    pub crypto_keys: Option<CryptoKeys>,
    // Decrypted organization keys: org_id -> keys
    #[serde(skip)]
    pub org_crypto_keys: HashMap<String, CryptoKeys>,
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
        let path = Self::keys_path()?;

        let user_keys = self.crypto_keys.as_ref().map(|keys| KeyData {
            enc_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.enc_key),
            mac_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.mac_key),
        });

        let org_keys: HashMap<String, KeyData> = self.org_crypto_keys.iter()
            .map(|(id, keys)| {
                (id.clone(), KeyData {
                    enc_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.enc_key),
                    mac_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &keys.mac_key),
                })
            })
            .collect();

        let saved = SavedKeys { user_keys, org_keys };
        let content = serde_json::to_string(&saved)?;
        fs::write(&path, content)?;

        Ok(())
    }

    pub fn load_saved_keys(&mut self) -> Result<()> {
        let path = Self::keys_path()?;
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let saved: SavedKeys = serde_json::from_str(&content)?;

            if let Some(keys_data) = saved.user_keys {
                let enc_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.enc_key)?;
                let mac_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.mac_key)?;
                self.crypto_keys = Some(CryptoKeys { enc_key, mac_key });
            }

            for (id, keys_data) in saved.org_keys {
                let enc_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.enc_key)?;
                let mac_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &keys_data.mac_key)?;
                self.org_crypto_keys.insert(id, CryptoKeys { enc_key, mac_key });
            }
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
        self.org_crypto_keys.clear();
        self.encrypted_key = None;
        self.encrypted_private_key = None;
        self.org_keys.clear();
        self.delete_saved_keys()?;
        self.save()
    }

    pub fn get_keys_for_cipher(&self, org_id: Option<&str>) -> Option<&CryptoKeys> {
        if let Some(org_id) = org_id {
            self.org_crypto_keys.get(org_id)
        } else {
            self.crypto_keys.as_ref()
        }
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
struct KeyData {
    enc_key: String,
    mac_key: String,
}

#[derive(Serialize, Deserialize, Default)]
struct SavedKeys {
    user_keys: Option<KeyData>,
    #[serde(default)]
    org_keys: HashMap<String, KeyData>,
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
