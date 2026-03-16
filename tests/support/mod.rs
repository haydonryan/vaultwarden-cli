#![allow(dead_code)]

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use anyhow::{Context, Result};
use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cbc::Encryptor;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;
use vaultwarden_cli::config::Config;
use vaultwarden_cli::crypto::CryptoKeys;
use vaultwarden_cli::models::{
    Cipher, CipherData, Collection, FieldData, Folder, LoginData, Organization, Profile,
    SyncResponse, TokenResponse, UriData,
};

type Aes256CbcEnc = Encryptor<aes::Aes256>;

pub struct TestContext {
    temp_dir: TempDir,
}

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl TestContext {
    pub fn new() -> Self {
        Self {
            temp_dir: TempDir::new().expect("create temp dir"),
        }
    }

    pub fn root(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn home_dir(&self) -> PathBuf {
        self.root().join("home")
    }

    pub fn config_root(&self) -> PathBuf {
        self.root().join("config-root")
    }

    pub fn set_process_env(&self) {
        std::fs::create_dir_all(self.home_dir()).expect("create home dir");
        std::fs::create_dir_all(self.config_root()).expect("create config root");
        unsafe {
            std::env::set_var("HOME", self.home_dir());
            std::env::set_var("XDG_CONFIG_HOME", self.config_root());
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            return self
                .home_dir()
                .join("Library")
                .join("Application Support")
                .join("com.vaultwarden.vaultwarden-cli");
        }

        #[cfg(not(target_os = "macos"))]
        {
            self.config_root().join("vaultwarden-cli")
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir().join("config.json")
    }

    pub fn keys_path(&self) -> PathBuf {
        self.config_dir().join("keys.json")
    }

    pub fn write_config(&self, config: &Config) -> Result<()> {
        if let Some(parent) = self.config_path().parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(config)?;
        fs::write(self.config_path(), content)?;
        Ok(())
    }

    pub fn write_raw_config(&self, content: &str) -> Result<()> {
        if let Some(parent) = self.config_path().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(self.config_path(), content)?;
        Ok(())
    }

    pub fn write_raw_keys(&self, content: &str) -> Result<()> {
        if let Some(parent) = self.keys_path().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(self.keys_path(), content)?;
        Ok(())
    }

    pub fn write_saved_user_keys(&self, keys: &CryptoKeys) -> Result<()> {
        self.write_raw_keys(&format!(
            r#"{{
                "user_keys": {{
                    "enc_key": "{}",
                    "mac_key": "{}"
                }},
                "org_keys": {{}}
            }}"#,
            BASE64.encode(&keys.enc_key),
            BASE64.encode(&keys.mac_key)
        ))
    }

    pub fn read_config_json(&self) -> Result<serde_json::Value> {
        let content = fs::read_to_string(self.config_path())?;
        serde_json::from_str(&content).context("parse config json")
    }

    pub fn binary(&self) -> Command {
        let mut cmd = Command::cargo_bin("vaultwarden-cli").expect("binary exists");
        cmd.env("HOME", self.home_dir());
        cmd.env("XDG_CONFIG_HOME", self.config_root());
        cmd
    }
}

pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned")
}

pub fn test_crypto_keys() -> CryptoKeys {
    CryptoKeys {
        enc_key: (0u8..32).collect(),
        mac_key: (32u8..64).collect(),
    }
}

pub fn encrypted_user_key(
    password: &str,
    email: &str,
    iterations: u32,
    keys: &CryptoKeys,
) -> String {
    let master_key = CryptoKeys::derive_master_key(password, email, iterations);
    let stretched = CryptoKeys::stretch_master_key(&master_key).expect("stretch master key");

    let mut symmetric_key = keys.enc_key.clone();
    symmetric_key.extend_from_slice(&keys.mac_key);

    encrypt_bytes_for_test(&symmetric_key, &stretched.enc_key, &stretched.mac_key)
}

pub fn encrypt_string_for_test(plaintext: &str, keys: &CryptoKeys) -> String {
    encrypt_bytes_for_test(plaintext.as_bytes(), &keys.enc_key, &keys.mac_key)
}

pub fn encrypt_bytes_for_test(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> String {
    let iv: Vec<u8> = (64u8..80).collect();
    let mut buf = plaintext.to_vec();
    let msg_len = buf.len();
    buf.resize(msg_len + 16, 0);

    let ciphertext = Aes256CbcEnc::new_from_slices(enc_key, &iv)
        .expect("cipher init")
        .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
        .expect("padding")
        .to_vec();

    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("hmac init");
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        BASE64.encode(&iv),
        BASE64.encode(&ciphertext),
        BASE64.encode(mac)
    )
}

pub fn token_response(access_token: &str) -> TokenResponse {
    TokenResponse {
        access_token: access_token.to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
        refresh_token: Some("refresh-token".to_string()),
        scope: Some("api".to_string()),
        key: Some("2.encrypted-key".to_string()),
        private_key: Some("2.encrypted-private-key".to_string()),
        kdf: Some(0),
        kdf_iterations: Some(600000),
    }
}

pub fn profile(email: &str) -> Profile {
    Profile {
        id: "user-1".to_string(),
        email: email.to_string(),
        name: Some("Test User".to_string()),
        key: None,
        private_key: None,
        organizations: Vec::new(),
    }
}

pub fn organization(id: &str, name: &str, key: Option<&str>) -> Organization {
    Organization {
        id: id.to_string(),
        name: Some(name.to_string()),
        key: key.map(str::to_string),
    }
}

pub fn collection(id: &str, name: &str, organization_id: &str) -> Collection {
    Collection {
        id: id.to_string(),
        name: name.to_string(),
        organization_id: organization_id.to_string(),
    }
}

pub fn folder(id: &str, name: &str) -> Folder {
    Folder {
        id: id.to_string(),
        name: name.to_string(),
    }
}

pub fn login_cipher(id: &str, name: &str, username: &str, password: &str, uri: &str) -> Cipher {
    Cipher {
        id: id.to_string(),
        r#type: 1,
        organization_id: None,
        name: Some(name.to_string()),
        notes: None,
        folder_id: None,
        login: Some(LoginData {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            totp: None,
            uris: Some(vec![UriData {
                uri: Some(uri.to_string()),
                r#match: Some(0),
            }]),
        }),
        card: None,
        identity: None,
        secure_note: None,
        collection_ids: Vec::new(),
        fields: None,
        data: None,
    }
}

pub fn nested_login_cipher(
    id: &str,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> Cipher {
    Cipher {
        id: id.to_string(),
        r#type: 1,
        organization_id: None,
        name: None,
        notes: None,
        folder_id: None,
        login: None,
        card: None,
        identity: None,
        secure_note: None,
        collection_ids: Vec::new(),
        fields: None,
        data: Some(CipherData {
            name: Some(name.to_string()),
            notes: None,
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            totp: None,
            uri: Some(uri.to_string()),
            uris: None,
            fields: None,
        }),
    }
}

pub fn field(name: &str, value: &str, hidden: bool) -> FieldData {
    FieldData {
        name: Some(name.to_string()),
        value: Some(value.to_string()),
        r#type: if hidden { 1 } else { 0 },
    }
}

pub fn sync_response(email: &str, ciphers: Vec<Cipher>) -> SyncResponse {
    SyncResponse {
        ciphers,
        folders: Vec::new(),
        collections: Vec::new(),
        profile: profile(email),
    }
}
