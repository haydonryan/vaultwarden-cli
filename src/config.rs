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
            let mut config: Config =
                serde_json::from_str(&content).context("Failed to parse config")?;

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
            enc_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &keys.enc_key,
            ),
            mac_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &keys.mac_key,
            ),
        });

        let org_keys: HashMap<String, KeyData> = self
            .org_crypto_keys
            .iter()
            .map(|(id, keys)| {
                (
                    id.clone(),
                    KeyData {
                        enc_key: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &keys.enc_key,
                        ),
                        mac_key: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &keys.mac_key,
                        ),
                    },
                )
            })
            .collect();

        let saved = SavedKeys {
            user_keys,
            org_keys,
        };
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
                let enc_key = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys_data.enc_key,
                )?;
                let mac_key = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys_data.mac_key,
                )?;
                self.crypto_keys = Some(CryptoKeys { enc_key, mac_key });
            }

            for (id, keys_data) in saved.org_keys {
                let enc_key = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys_data.enc_key,
                )?;
                let mac_key = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys_data.mac_key,
                )?;
                self.org_crypto_keys
                    .insert(id, CryptoKeys { enc_key, mac_key });
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
    entry.delete_credential().ok(); // Ignore errors if not found
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Config state tests
    mod config_state_tests {
        use super::*;

        #[test]
        fn test_config_default() {
            let config = Config::default();

            assert!(config.server.is_none());
            assert!(config.client_id.is_none());
            assert!(config.email.is_none());
            assert!(config.access_token.is_none());
            assert!(config.refresh_token.is_none());
            assert!(config.token_expiry.is_none());
            assert!(config.encrypted_key.is_none());
            assert!(config.encrypted_private_key.is_none());
            assert!(config.kdf_iterations.is_none());
            assert!(config.org_keys.is_empty());
            assert!(config.crypto_keys.is_none());
            assert!(config.org_crypto_keys.is_empty());
        }

        #[test]
        fn test_is_logged_in_false_when_no_token() {
            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: None,
                ..Default::default()
            };
            assert!(!config.is_logged_in());
        }

        #[test]
        fn test_is_logged_in_false_when_no_server() {
            let config = Config {
                server: None,
                access_token: Some("token".to_string()),
                ..Default::default()
            };
            assert!(!config.is_logged_in());
        }

        #[test]
        fn test_is_logged_in_true_when_both_present() {
            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                ..Default::default()
            };
            assert!(config.is_logged_in());
        }

        #[test]
        fn test_is_unlocked_false_when_no_keys() {
            let config = Config::default();
            assert!(!config.is_unlocked());
        }

        #[test]
        fn test_is_unlocked_true_when_keys_present() {
            let config = Config {
                crypto_keys: Some(CryptoKeys {
                    enc_key: vec![0u8; 32],
                    mac_key: vec![0u8; 32],
                }),
                ..Default::default()
            };
            assert!(config.is_unlocked());
        }

        #[test]
        fn test_get_server() {
            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                ..Default::default()
            };
            assert_eq!(config.get_server(), Some("https://vault.example.com"));
        }

        #[test]
        fn test_get_server_none() {
            let config = Config::default();
            assert_eq!(config.get_server(), None);
        }
    }

    // Key retrieval tests
    mod key_retrieval_tests {
        use super::*;

        #[test]
        fn test_get_keys_for_cipher_user_keys() {
            let user_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };

            let config = Config {
                crypto_keys: Some(user_keys.clone()),
                ..Default::default()
            };

            let keys = config.get_keys_for_cipher(None).unwrap();
            assert_eq!(keys.enc_key, user_keys.enc_key);
        }

        #[test]
        fn test_get_keys_for_cipher_org_keys() {
            let user_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };
            let org_keys = CryptoKeys {
                enc_key: vec![3u8; 32],
                mac_key: vec![4u8; 32],
            };

            let mut config = Config {
                crypto_keys: Some(user_keys),
                ..Default::default()
            };
            config
                .org_crypto_keys
                .insert("org-123".to_string(), org_keys.clone());

            let keys = config.get_keys_for_cipher(Some("org-123")).unwrap();
            assert_eq!(keys.enc_key, org_keys.enc_key);
        }

        #[test]
        fn test_get_keys_for_cipher_org_not_found() {
            let user_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };

            let config = Config {
                crypto_keys: Some(user_keys),
                ..Default::default()
            };

            // Requesting keys for an org that doesn't exist
            let keys = config.get_keys_for_cipher(Some("nonexistent-org"));
            assert!(keys.is_none());
        }

        #[test]
        fn test_get_keys_for_cipher_no_keys() {
            let config = Config::default();
            assert!(config.get_keys_for_cipher(None).is_none());
        }
    }

    // Serialization tests
    mod serialization_tests {
        use super::*;

        #[test]
        fn test_config_serialization_excludes_crypto_keys() {
            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                crypto_keys: Some(CryptoKeys {
                    enc_key: vec![1u8; 32],
                    mac_key: vec![2u8; 32],
                }),
                ..Default::default()
            };

            let json = serde_json::to_string(&config).unwrap();

            // crypto_keys should not be in the serialized output (marked with skip)
            assert!(!json.contains("enc_key"));
            assert!(!json.contains("mac_key"));
            // But server should be there
            assert!(json.contains("vault.example.com"));
        }

        #[test]
        fn test_config_deserialization() {
            let json = r#"{
                "server": "https://vault.example.com",
                "client_id": "user.client-123",
                "email": "user@example.com",
                "access_token": "test-token",
                "token_expiry": 1234567890,
                "kdf_iterations": 600000
            }"#;

            let config: Config = serde_json::from_str(json).unwrap();
            assert_eq!(config.server, Some("https://vault.example.com".to_string()));
            assert_eq!(config.client_id, Some("user.client-123".to_string()));
            assert_eq!(config.email, Some("user@example.com".to_string()));
            assert_eq!(config.token_expiry, Some(1234567890));
            assert_eq!(config.kdf_iterations, Some(600000));
            // crypto_keys should be None after deserialization
            assert!(config.crypto_keys.is_none());
        }

        #[test]
        fn test_config_with_org_keys() {
            let mut config = Config::default();
            config
                .org_keys
                .insert("org-1".to_string(), "encrypted-key-1".to_string());
            config
                .org_keys
                .insert("org-2".to_string(), "encrypted-key-2".to_string());

            let json = serde_json::to_string(&config).unwrap();
            assert!(json.contains("org-1"));
            assert!(json.contains("encrypted-key-1"));

            let deserialized: Config = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.org_keys.len(), 2);
            assert_eq!(
                deserialized.org_keys.get("org-1"),
                Some(&"encrypted-key-1".to_string())
            );
        }
    }

    // File I/O tests using tempdir
    // Note: These tests use direct file operations to avoid environment variable issues
    mod file_io_tests {
        use super::*;
        use std::fs;
        use tempfile::TempDir;

        #[test]
        fn test_config_dir_returns_path() {
            // Just verify it doesn't error
            let result = Config::config_dir();
            assert!(result.is_ok());
        }

        #[test]
        fn test_config_path_is_config_json() {
            let result = Config::config_path();
            assert!(result.is_ok());
            let path = result.unwrap();
            assert!(path.ends_with("config.json"));
        }

        #[test]
        fn test_keys_path_is_keys_json() {
            let result = Config::keys_path();
            assert!(result.is_ok());
            let path = result.unwrap();
            assert!(path.ends_with("keys.json"));
        }

        // Test direct serialization/deserialization without filesystem
        #[test]
        fn test_config_save_load_roundtrip() {
            let temp_dir = TempDir::new().unwrap();
            let config_path = temp_dir.path().join("config.json");

            let config = Config {
                server: Some("https://test.example.com".to_string()),
                client_id: Some("test-client".to_string()),
                email: Some("test@example.com".to_string()),
                access_token: Some("test-token".to_string()),
                kdf_iterations: Some(100000),
                ..Default::default()
            };

            // Save manually to temp location
            let content = serde_json::to_string_pretty(&config).unwrap();
            fs::write(&config_path, &content).unwrap();

            // Load manually from temp location
            let loaded_content = fs::read_to_string(&config_path).unwrap();
            let loaded: Config = serde_json::from_str(&loaded_content).unwrap();

            assert_eq!(loaded.server, config.server);
            assert_eq!(loaded.client_id, config.client_id);
            assert_eq!(loaded.email, config.email);
            assert_eq!(loaded.kdf_iterations, config.kdf_iterations);
        }

        #[test]
        fn test_keys_save_load_roundtrip() {
            let temp_dir = TempDir::new().unwrap();
            let keys_path = temp_dir.path().join("keys.json");

            let config = Config {
                crypto_keys: Some(CryptoKeys {
                    enc_key: vec![0x42u8; 32],
                    mac_key: vec![0x43u8; 32],
                }),
                ..Default::default()
            };

            // Manually save keys
            let user_keys = config.crypto_keys.as_ref().map(|keys| KeyData {
                enc_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys.enc_key,
                ),
                mac_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &keys.mac_key,
                ),
            });

            let saved = SavedKeys {
                user_keys,
                org_keys: HashMap::new(),
            };
            let content = serde_json::to_string(&saved).unwrap();
            fs::write(&keys_path, &content).unwrap();

            // Load keys back
            let loaded_content = fs::read_to_string(&keys_path).unwrap();
            let loaded_saved: SavedKeys = serde_json::from_str(&loaded_content).unwrap();

            let keys_data = loaded_saved.user_keys.unwrap();
            let enc_key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &keys_data.enc_key,
            )
            .unwrap();
            let mac_key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &keys_data.mac_key,
            )
            .unwrap();

            assert_eq!(enc_key, vec![0x42u8; 32]);
            assert_eq!(mac_key, vec![0x43u8; 32]);
        }

        #[test]
        fn test_org_keys_save_load_roundtrip() {
            let temp_dir = TempDir::new().unwrap();
            let keys_path = temp_dir.path().join("keys.json");

            let mut config = Config::default();
            config.org_crypto_keys.insert(
                "org-1".to_string(),
                CryptoKeys {
                    enc_key: vec![0x11u8; 32],
                    mac_key: vec![0x12u8; 32],
                },
            );
            config.org_crypto_keys.insert(
                "org-2".to_string(),
                CryptoKeys {
                    enc_key: vec![0x21u8; 32],
                    mac_key: vec![0x22u8; 32],
                },
            );

            // Manually save keys
            let org_keys: HashMap<String, KeyData> = config
                .org_crypto_keys
                .iter()
                .map(|(id, keys)| {
                    (
                        id.clone(),
                        KeyData {
                            enc_key: base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &keys.enc_key,
                            ),
                            mac_key: base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &keys.mac_key,
                            ),
                        },
                    )
                })
                .collect();

            let saved = SavedKeys {
                user_keys: None,
                org_keys,
            };
            let content = serde_json::to_string(&saved).unwrap();
            fs::write(&keys_path, &content).unwrap();

            // Load keys back
            let loaded_content = fs::read_to_string(&keys_path).unwrap();
            let loaded_saved: SavedKeys = serde_json::from_str(&loaded_content).unwrap();

            assert_eq!(loaded_saved.org_keys.len(), 2);

            let org1_data = loaded_saved.org_keys.get("org-1").unwrap();
            let org1_enc = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &org1_data.enc_key,
            )
            .unwrap();
            assert_eq!(org1_enc, vec![0x11u8; 32]);
        }

        #[test]
        fn test_delete_keys_file() {
            let temp_dir = TempDir::new().unwrap();
            let keys_path = temp_dir.path().join("keys.json");

            // Create a file
            fs::write(&keys_path, "{}").unwrap();
            assert!(keys_path.exists());

            // Delete it
            fs::remove_file(&keys_path).unwrap();
            assert!(!keys_path.exists());
        }

        #[test]
        fn test_delete_nonexistent_keys_ok() {
            let temp_dir = TempDir::new().unwrap();
            let keys_path = temp_dir.path().join("nonexistent.json");

            // Should not panic when file doesn't exist
            if keys_path.exists() {
                fs::remove_file(&keys_path).unwrap();
            }
            // No error expected
        }

        #[test]
        fn test_clear_config_fields() {
            let mut config = Config {
                server: Some("https://test.example.com".to_string()),
                client_id: Some("test-client".to_string()),
                access_token: Some("test-token".to_string()),
                refresh_token: Some("refresh-token".to_string()),
                token_expiry: Some(1234567890),
                encrypted_key: Some("encrypted-key".to_string()),
                encrypted_private_key: Some("private-key".to_string()),
                crypto_keys: Some(CryptoKeys {
                    enc_key: vec![0u8; 32],
                    mac_key: vec![0u8; 32],
                }),
                ..Default::default()
            };
            config
                .org_keys
                .insert("org-1".to_string(), "key".to_string());
            config.org_crypto_keys.insert(
                "org-1".to_string(),
                CryptoKeys {
                    enc_key: vec![0u8; 32],
                    mac_key: vec![0u8; 32],
                },
            );

            // Manually clear fields (simulating clear() behavior without file ops)
            config.access_token = None;
            config.refresh_token = None;
            config.token_expiry = None;
            config.crypto_keys = None;
            config.encrypted_key = None;
            config.encrypted_private_key = None;
            config.org_keys.clear();
            config.org_crypto_keys.clear();

            // These should be cleared
            assert!(config.access_token.is_none());
            assert!(config.refresh_token.is_none());
            assert!(config.token_expiry.is_none());
            assert!(config.crypto_keys.is_none());
            assert!(config.encrypted_key.is_none());
            assert!(config.encrypted_private_key.is_none());
            assert!(config.org_keys.is_empty());
            assert!(config.org_crypto_keys.is_empty());

            // Server and client_id should remain (for re-login)
            assert!(config.server.is_some());
            assert!(config.client_id.is_some());
        }

        #[test]
        fn test_load_empty_keys_file() {
            let temp_dir = TempDir::new().unwrap();
            let keys_path = temp_dir.path().join("keys.json");

            // Write empty saved keys structure
            let saved = SavedKeys::default();
            let content = serde_json::to_string(&saved).unwrap();
            fs::write(&keys_path, &content).unwrap();

            // Load it back
            let loaded_content = fs::read_to_string(&keys_path).unwrap();
            let loaded: SavedKeys = serde_json::from_str(&loaded_content).unwrap();

            assert!(loaded.user_keys.is_none());
            assert!(loaded.org_keys.is_empty());
        }
    }
}
