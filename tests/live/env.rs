//! Live test environment: provision a real Vaultwarden user + vault items,
//! expose a pre-configured `Command` builder, and clean up on drop.
//!
//! Gated by the environment variables:
//!   VAULTWARDEN_LIVE_TEST_URL     — URL of a running Vaultwarden instance
//!   VAULTWARDEN_LIVE_ADMIN_TOKEN  — admin token for user teardown
//!
//! If either variable is absent every test module that calls
//! `LiveTestEnv::maybe_create().await` will simply return early (skip).
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Context, Result};
use assert_cmd::Command;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use cbc::Encryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use reqwest::{Client, ClientBuilder};
use serde_json::{Value, json};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use vaultwarden_cli::crypto::CryptoKeys;

type Aes256CbcEnc = Encryptor<aes::Aes256>;

// ── Fixed test credentials ─────────────────────────────────────────────────

/// Master password used for every test user.
pub const TEST_PASSWORD: &str = "LiveTest-P@ss!1"; // secrets-ignore: test fixture

// ── Fixture constants ──────────────────────────────────────────────────────

pub const FIXTURE_FOLDER_NAME: &str = "Live-Test-Folder";

pub const FIXTURE_LOGIN_NAME: &str = "Live-Test-Login";
pub const FIXTURE_LOGIN_USERNAME: &str = "testuser@example.com";
pub const FIXTURE_LOGIN_PASSWORD: &str = "P@ssword123!"; // secrets-ignore: test fixture
pub const FIXTURE_LOGIN_URI: &str = "https://live-test.example.com/login";
pub const FIXTURE_LOGIN_FIELD_API_KEY_NAME: &str = "api_key";
pub const FIXTURE_LOGIN_FIELD_API_KEY_VALUE: &str = "test-api-key-abc";
pub const FIXTURE_LOGIN_FIELD_SECRET_NAME: &str = "secret";
pub const FIXTURE_LOGIN_FIELD_SECRET_VALUE: &str = "hidden-secret-xyz";

pub const FIXTURE_LOGIN2_NAME: &str = "Live-Test-Login-2";
pub const FIXTURE_LOGIN2_USERNAME: &str = "second@example.com";
pub const FIXTURE_LOGIN2_PASSWORD: &str = "Second123!"; // secrets-ignore: test fixture
pub const FIXTURE_LOGIN2_URI: &str = "https://second.example.com/app";

pub const FIXTURE_NOTE_NAME: &str = "Live-Test-Note";
pub const FIXTURE_NOTE_CONTENT: &str = "This is a live test note.";

pub const FIXTURE_CARD_NAME: &str = "Live-Test-Card";
pub const FIXTURE_CARD_NUMBER: &str = "4111111111111111";
pub const FIXTURE_CARD_EXPIRY_MONTH: &str = "12";
pub const FIXTURE_CARD_EXPIRY_YEAR: &str = "2030";
pub const FIXTURE_CARD_HOLDER: &str = "Test User";

pub const FIXTURE_SSH_NAME: &str = "Live-Test-SSH";
pub const FIXTURE_SSH_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI live-test-public-key";
pub const FIXTURE_SSH_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH ",
    "PRIVATE KEY-----\n",
    "live-test-private-key-not-real\n",
    "-----END OPENSSH PRIVATE KEY-----",
);
pub const FIXTURE_SSH_FINGERPRINT: &str = "SHA256:liveTestFingerprint1234";

// ── LiveTestEnv ────────────────────────────────────────────────────────────

/// A self-contained live test environment.
///
/// Creates a throwaway Vaultwarden user, provisions vault fixtures, writes
/// config/token/key files to a temp directory, and deletes the user on drop.
pub struct LiveTestEnv {
    _temp_dir: TempDir,
    /// $HOME set for the test binary
    pub home_dir: PathBuf,
    /// XDG_CONFIG_HOME set for the test binary
    pub config_root: PathBuf,
    /// Actual vaultwarden-cli config directory inside config_root
    pub config_dir: PathBuf,
    /// Vaultwarden server URL
    pub server_url: String,
    /// Test user email
    pub email: String,
    /// API client_id (from rotate-api-key)
    pub client_id: String,
    /// API client_secret (from rotate-api-key)
    pub client_secret: String,
    /// User UUID for admin teardown
    user_uuid: String,
    /// Admin token for teardown
    admin_token: String,
    /// Resolved folder ID
    pub folder_id: String,
    /// Item IDs from the server
    pub login_item_id: String,
    pub login2_item_id: String,
    pub note_item_id: String,
    pub card_item_id: String,
    pub ssh_item_id: String,
    /// Plaintext user keys (for assertions / additional cipher creation)
    pub user_keys: CryptoKeys,
}

impl LiveTestEnv {
    /// Returns `None` when live-test env vars are not set (tests skip silently).
    /// Returns `Some(env)` with a fully provisioned environment.
    pub async fn maybe_create() -> Option<Self> {
        let server_url = std::env::var("VAULTWARDEN_LIVE_TEST_URL").ok()?;
        let admin_token = std::env::var("VAULTWARDEN_LIVE_ADMIN_TOKEN").ok()?;
        Some(
            Self::create(server_url, admin_token)
                .await
                .expect("LiveTestEnv::create failed"),
        )
    }

    /// Build a `Command` for the `vaultwarden-cli` binary with the correct
    /// HOME/XDG_CONFIG_HOME and HTTP-allow env vars pointing at our temp dir.
    pub fn binary(&self) -> Command {
        let mut cmd = Command::cargo_bin("vaultwarden-cli").expect("vaultwarden-cli binary");
        cmd.env("HOME", &self.home_dir);
        cmd.env("XDG_CONFIG_HOME", &self.config_root);
        // The test server uses plain HTTP; tell the CLI to accept it.
        cmd.env("VAULTWARDEN_ALLOW_HTTP", "1");
        // Live tests capture stdout and assert JSON payloads intentionally.
        cmd.env("VAULTWARDEN_ALLOW_PLAINTEXT_JSON", "true");
        // Live fixtures intentionally use isolated legacy keys.json storage.
        cmd.env("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE", "true");
        // Disable keyring so tests stay file-based and fully isolated.
        cmd.env("KEYRING_BACKEND", "plaintext");
        cmd
    }

    /// Build a binary command with VAULTWARDEN_PASSWORD pre-set.
    pub fn binary_with_password(&self) -> Command {
        let mut cmd = self.binary();
        cmd.env("VAULTWARDEN_PASSWORD", TEST_PASSWORD);
        cmd
    }

    /// Remove keys.json so the vault appears locked to the binary.
    pub fn lock_vault(&self) {
        let path = self.config_dir.join("keys.json");
        drop(std::fs::remove_file(path));
    }

    /// Remove all session files so the binary sees a fresh (logged-out) state.
    pub fn clear_session(&self) {
        for name in ["config.json", "tokens.json", "keys.json"] {
            drop(std::fs::remove_file(self.config_dir.join(name)));
        }
    }

    /// Re-write a fresh tokens.json so that subsequent commands can auth.
    /// Called after tests that exercise logout (which deletes tokens.json).
    pub async fn restore_session(&self, access_token: &str, refresh_token: Option<&str>) {
        let expiry = unix_now() + 3600;
        let tokens_json = json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": expiry,
        });
        let path = self.config_dir.join("tokens.json");
        std::fs::write(&path, serde_json::to_string(&tokens_json).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            drop(std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o600),
            ));
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────

    async fn create(server_url: String, admin_token: String) -> Result<Self> {
        let http = Client::new();

        // Unique per-test credentials (8-hex suffix prevents collisions).
        let suffix = random_hex(8);
        let email = format!("live-test-{suffix}@test.invalid");
        let device_id = format!("live-test-device-{suffix}");

        // Lower iteration count for test speed (still exercises the full
        // key-derivation path; the exact count is stored in config.json so
        // the unlock command will use the same value).
        let kdf_iterations: u32 = 100_000;

        // ── Crypto material ──────────────────────────────────────────────
        let master_key = CryptoKeys::derive_master_key(TEST_PASSWORD, &email, kdf_iterations);
        let stretched = CryptoKeys::stretch_master_key(&master_key)?;

        // Random 64-byte symmetric key: [enc_key(32) | mac_key(32)]
        let mut sym_key_bytes = [0u8; 64];
        rand::rng().fill_bytes(&mut sym_key_bytes);

        // Protect the symmetric key with the stretched master key.
        let protected_key = encrypt_bytes(&sym_key_bytes, &stretched.enc_key, &stretched.mac_key);

        // Master-password hash sent to the server (PBKDF2 round 2).
        let pw_hash = master_password_hash(&master_key, TEST_PASSWORD);

        // ── Register user ────────────────────────────────────────────────
        // Vaultwarden ≥1.30 moved registration to /identity/accounts/register.
        let reg_resp = http
            .post(format!("{server_url}/identity/accounts/register"))
            .json(&json!({
                "email": email,
                "name": "Live Test User",
                "masterPasswordHash": pw_hash,
                "masterPasswordHint": "",
                "key": protected_key,
                "kdfType": 0,
                "kdfIterations": kdf_iterations,
            }))
            .send()
            .await
            .context("registration request")?;

        ensure_ok(&reg_resp.status(), reg_resp.text().await.ok(), "register")?;

        // ── Password grant → bearer token ────────────────────────────────
        let bearer = password_grant(&http, &server_url, &email, &pw_hash, &device_id).await?;

        // ── User UUID (from sync profile) ────────────────────────────────
        let sync: Value = http
            .get(format!("{server_url}/api/sync"))
            .bearer_auth(&bearer)
            .send()
            .await
            .context("sync request")?
            .json()
            .await
            .context("parse sync")?;

        let user_uuid = sync["Profile"]["Id"]
            .as_str()
            .or_else(|| sync["profile"]["id"].as_str())
            .with_context(|| format!("no profile ID in sync: {sync}"))?
            .to_string();

        // ── Rotate API key → client_id + client_secret ───────────────────
        let rotate: Value = http
            .post(format!("{server_url}/api/accounts/rotate-api-key"))
            .bearer_auth(&bearer)
            .json(&json!({"masterPasswordHash": pw_hash}))
            .send()
            .await
            .context("rotate-api-key request")?
            .json()
            .await
            .context("parse rotate-api-key")?;

        // Vaultwarden returns {"apiKey":"<secret>","object":"apiKey",...}
        // The client_id is always "user.<uuid>" and is not returned in this response.
        let client_id = format!("user.{user_uuid}");
        let client_secret = rotate["apiKey"]
            .as_str()
            .or_else(|| rotate["ApiKey"].as_str())
            .or_else(|| rotate["ClientSecret"].as_str())
            .or_else(|| rotate["clientSecret"].as_str())
            .with_context(|| format!("no apiKey in rotate-api-key: {rotate}"))?
            .to_string();

        // ── Client-credentials grant → access token + encrypted key ──────
        let api_tok: Value = http
            .post(format!("{server_url}/identity/connect/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("deviceType", "14"),
                ("deviceIdentifier", device_id.as_str()),
                ("deviceName", "vaultwarden-cli-live-test"),
            ])
            .send()
            .await
            .context("client_credentials grant")?
            .json()
            .await
            .context("parse client_credentials response")?;

        let access_token = api_tok["access_token"]
            .as_str()
            .context("no access_token")?
            .to_string();
        let refresh_token = api_tok["refresh_token"].as_str().map(str::to_string);
        let expires_in = api_tok["expires_in"].as_i64().unwrap_or(3600);
        let token_expiry = unix_now() + expires_in;

        // The server echoes back the protected key we registered with,
        // possibly in a different casing.
        let encrypted_key_from_server = api_tok["Key"]
            .as_str()
            .or_else(|| api_tok["key"].as_str())
            .unwrap_or(&protected_key)
            .to_string();

        // Reconstruct user keys from plaintext (we know them since we
        // generated them during registration).
        let user_keys = CryptoKeys::from_symmetric_key(&sym_key_bytes)?;

        // ── Temp directory layout ────────────────────────────────────────
        let temp_dir = TempDir::new().context("TempDir")?;
        let home_dir = temp_dir.path().join("home");
        let config_root = temp_dir.path().join("config-root");
        let config_dir = config_root.join("vaultwarden-cli");
        std::fs::create_dir_all(&home_dir)?;
        std::fs::create_dir_all(&config_dir)?;

        // ── config.json ──────────────────────────────────────────────────
        write_json(
            &config_dir.join("config.json"),
            &json!({
                "server": server_url,
                "client_id": client_id,
                "email": email,
                "encrypted_key": encrypted_key_from_server,
                "kdf_iterations": kdf_iterations,
                "org_keys": {},
            }),
            0o600,
        )?;

        // ── tokens.json ──────────────────────────────────────────────────
        write_json(
            &config_dir.join("tokens.json"),
            &json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_expiry": token_expiry,
            }),
            0o600,
        )?;

        // ── keys.json (vault unlocked by default in provisioned env) ─────
        write_secret_file(
            &config_dir.join("keys.json"),
            &format!(
                r#"{{"user_keys":{{"enc_key":"{}","mac_key":"{}"}},"org_keys":{{}}}}"#,
                BASE64.encode(&user_keys.enc_key),
                BASE64.encode(&user_keys.mac_key),
            ),
        )?;

        // ── Vault fixtures ───────────────────────────────────────────────
        let folder_id = create_folder(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_FOLDER_NAME,
        )
        .await?;

        let login_item_id = create_login(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_LOGIN_NAME,
            FIXTURE_LOGIN_USERNAME,
            FIXTURE_LOGIN_PASSWORD,
            FIXTURE_LOGIN_URI,
            Some(&folder_id),
            &[
                (
                    FIXTURE_LOGIN_FIELD_API_KEY_NAME,
                    FIXTURE_LOGIN_FIELD_API_KEY_VALUE,
                    false,
                ),
                (
                    FIXTURE_LOGIN_FIELD_SECRET_NAME,
                    FIXTURE_LOGIN_FIELD_SECRET_VALUE,
                    true,
                ),
            ],
        )
        .await?;

        let login2_item_id = create_login(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_LOGIN2_NAME,
            FIXTURE_LOGIN2_USERNAME,
            FIXTURE_LOGIN2_PASSWORD,
            FIXTURE_LOGIN2_URI,
            None,
            &[],
        )
        .await?;

        let note_item_id = create_note(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_NOTE_NAME,
            FIXTURE_NOTE_CONTENT,
        )
        .await?;

        let card_item_id = create_card(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_CARD_NAME,
            FIXTURE_CARD_NUMBER,
            FIXTURE_CARD_EXPIRY_MONTH,
            FIXTURE_CARD_EXPIRY_YEAR,
            FIXTURE_CARD_HOLDER,
        )
        .await?;

        let ssh_item_id = create_ssh(
            &http,
            &server_url,
            &access_token,
            &user_keys,
            FIXTURE_SSH_NAME,
            FIXTURE_SSH_PUBLIC_KEY,
            FIXTURE_SSH_PRIVATE_KEY,
            FIXTURE_SSH_FINGERPRINT,
        )
        .await?;

        Ok(Self {
            _temp_dir: temp_dir,
            home_dir,
            config_root,
            config_dir,
            server_url,
            email,
            client_id,
            client_secret,
            user_uuid,
            admin_token,
            folder_id,
            login_item_id,
            login2_item_id,
            note_item_id,
            card_item_id,
            ssh_item_id,
            user_keys,
        })
    }
}

impl Drop for LiveTestEnv {
    fn drop(&mut self) {
        // Best-effort: delete the test user so volatile-storage instances don't
        // accumulate entries.  Failure is silently ignored (the container is
        // typically torn down immediately after the test run anyway).
        //
        // Vaultwarden ≥1.30 admin API requires a session JWT obtained by POSTing
        // the raw admin token to /admin.  We do that first, then use the cookie.
        let delete_url = format!("{}/admin/users/{}/delete", self.server_url, self.user_uuid);
        let admin_login_url = format!("{}/admin", self.server_url);
        let admin_token = self.admin_token.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                rt.block_on(async {
                    let timeout = std::time::Duration::from_secs(5);
                    let client = ClientBuilder::new()
                        .timeout(timeout)
                        .build()
                        .unwrap_or_else(|_| Client::new());
                    // Step 1: Login to get the VW_ADMIN session JWT.
                    let params = [("token", admin_token.as_str())];
                    let login_resp = client.post(&admin_login_url).form(&params).send().await;
                    if let Ok(resp) = login_resp {
                        // Extract the JWT from the Set-Cookie header.
                        let jwt = resp
                            .headers()
                            .get_all("set-cookie")
                            .iter()
                            .filter_map(|v| v.to_str().ok())
                            .find(|v| v.starts_with("VW_ADMIN="))
                            .and_then(|v| v.split(';').next())
                            .and_then(|v| v.strip_prefix("VW_ADMIN="))
                            .map(str::to_string);
                        if let Some(jwt) = jwt {
                            // Step 2: Delete the user with the JWT as Bearer.
                            drop(
                                client
                                    .post(&delete_url)
                                    .header("Authorization", format!("Bearer {jwt}"))
                                    .send()
                                    .await,
                            );
                        }
                    }
                });
            }
        });
        // Do not join — teardown is best-effort; we don't want Drop to block
        // the test runner if Vaultwarden is slow or already gone.
    }
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

/// Encrypt arbitrary bytes using AES-256-CBC + HMAC-SHA256 with a random IV.
/// Returns a Bitwarden-format string: `"2.<iv>|<ciphertext>|<mac>"`.
pub fn encrypt_bytes(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> String {
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let mut buf = plaintext.to_vec();
    let msg_len = buf.len();
    buf.resize(msg_len + 16, 0); // room for PKCS#7 padding

    let ciphertext = Aes256CbcEnc::new_from_slices(enc_key, &iv)
        .expect("cipher init")
        .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
        .expect("encrypt")
        .to_vec();

    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("hmac init");
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        BASE64.encode(iv),
        BASE64.encode(&ciphertext),
        BASE64.encode(mac)
    )
}

/// Encrypt a UTF-8 string using the given `CryptoKeys`.
pub fn encrypt_str(plaintext: &str, keys: &CryptoKeys) -> String {
    encrypt_bytes(plaintext.as_bytes(), &keys.enc_key, &keys.mac_key)
}

/// Compute the Bitwarden master-password hash:
///   PBKDF2-SHA256(master_key, password_bytes, 1) → base64
fn master_password_hash(master_key: &[u8], password: &str) -> String {
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    BASE64.encode(hash)
}

// ── Network helpers ────────────────────────────────────────────────────────

/// Exchange email + master-password-hash for a bearer token via the
/// Bitwarden password-grant endpoint.
async fn password_grant(
    http: &Client,
    server_url: &str,
    email: &str,
    pw_hash: &str,
    device_id: &str,
) -> Result<String> {
    let resp: Value = http
        .post(format!("{server_url}/identity/connect/token"))
        .form(&[
            ("grant_type", "password"),
            ("username", email),
            ("password", pw_hash),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "9"),
            ("deviceIdentifier", device_id),
            ("deviceName", "live-test-browser"),
        ])
        .send()
        .await
        .context("password grant request")?
        .json()
        .await
        .context("parse password grant")?;

    resp["access_token"]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("no access_token in password grant: {resp}"))
}

fn ensure_ok(status: &reqwest::StatusCode, body: Option<String>, operation: &str) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    let text = body.unwrap_or_default();
    anyhow::bail!("{operation} failed ({status}): {text}")
}

// ── Cipher creation helpers ────────────────────────────────────────────────

async fn post_cipher(
    http: &Client,
    server_url: &str,
    access_token: &str,
    body: serde_json::Value,
) -> Result<String> {
    let resp = http
        .post(format!("{server_url}/api/ciphers"))
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await
        .context("create cipher request")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("create cipher failed ({status}): {text}");
    }

    let parsed: Value = serde_json::from_str(&text).context("parse cipher response")?;
    parsed["Id"]
        .as_str()
        .or_else(|| parsed["id"].as_str())
        .map(str::to_string)
        .with_context(|| format!("no ID in cipher response: {parsed}"))
}

async fn create_folder(
    http: &Client,
    server_url: &str,
    access_token: &str,
    keys: &CryptoKeys,
    name: &str,
) -> Result<String> {
    let resp = http
        .post(format!("{server_url}/api/folders"))
        .bearer_auth(access_token)
        .json(&json!({"name": encrypt_str(name, keys)}))
        .send()
        .await
        .context("create folder request")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("create folder failed ({status}): {text}");
    }

    let parsed: Value = serde_json::from_str(&text).context("parse folder response")?;
    parsed["Id"]
        .as_str()
        .or_else(|| parsed["id"].as_str())
        .map(str::to_string)
        .with_context(|| format!("no ID in folder response: {parsed}"))
}

#[allow(clippy::too_many_arguments)]
async fn create_login(
    http: &Client,
    server_url: &str,
    access_token: &str,
    keys: &CryptoKeys,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
    folder_id: Option<&str>,
    fields: &[(&str, &str, bool)],
) -> Result<String> {
    let enc_fields: Vec<Value> = fields
        .iter()
        .map(|(n, v, hidden)| {
            json!({
                "type": if *hidden { 1u8 } else { 0u8 },
                "name": encrypt_str(n, keys),
                "value": encrypt_str(v, keys),
            })
        })
        .collect();

    post_cipher(
        http,
        server_url,
        access_token,
        json!({
            "type": 1,
            "name": encrypt_str(name, keys),
            "folderId": folder_id,
            "notes": null,
            "login": {
                "username": encrypt_str(username, keys),
                "password": encrypt_str(password, keys),
                "uris": [{"uri": encrypt_str(uri, keys), "match": null}],
            },
            "fields": enc_fields,
            "favorite": false,
            "reprompt": 0,
        }),
    )
    .await
}

async fn create_note(
    http: &Client,
    server_url: &str,
    access_token: &str,
    keys: &CryptoKeys,
    name: &str,
    notes: &str,
) -> Result<String> {
    post_cipher(
        http,
        server_url,
        access_token,
        json!({
            "type": 2,
            "name": encrypt_str(name, keys),
            "notes": encrypt_str(notes, keys),
            "secureNote": {"type": 0},
            "favorite": false,
            "reprompt": 0,
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_card(
    http: &Client,
    server_url: &str,
    access_token: &str,
    keys: &CryptoKeys,
    name: &str,
    number: &str,
    exp_month: &str,
    exp_year: &str,
    cardholder: &str,
) -> Result<String> {
    post_cipher(
        http,
        server_url,
        access_token,
        json!({
            "type": 3,
            "name": encrypt_str(name, keys),
            "notes": null,
            "card": {
                "cardholderName": encrypt_str(cardholder, keys),
                "number": encrypt_str(number, keys),
                "expMonth": encrypt_str(exp_month, keys),
                "expYear": encrypt_str(exp_year, keys),
                "code": null,
                "brand": null,
            },
            "favorite": false,
            "reprompt": 0,
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_ssh(
    http: &Client,
    server_url: &str,
    access_token: &str,
    keys: &CryptoKeys,
    name: &str,
    public_key: &str,
    private_key: &str,
    fingerprint: &str,
) -> Result<String> {
    // Type 5 = SSH key.  Vaultwarden may return a 400 if SSH keys are not
    // supported in the installed version; in that case fall back to a login
    // item with custom fields so the rest of the test suite still works.
    let body = json!({
        "type": 5,
        "name": encrypt_str(name, keys),
        "notes": null,
        "sshKey": {
            "publicKey": encrypt_str(public_key, keys),
            "privateKey": encrypt_str(private_key, keys),
            "keyFingerprint": encrypt_str(fingerprint, keys),
        },
        "favorite": false,
        "reprompt": 0,
    });

    let resp = http
        .post(format!("{server_url}/api/ciphers"))
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await
        .context("create ssh cipher request")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if status.is_success() {
        let parsed: Value = serde_json::from_str(&text).context("parse ssh cipher response")?;
        return parsed["Id"]
            .as_str()
            .or_else(|| parsed["id"].as_str())
            .map(str::to_string)
            .with_context(|| format!("no ID in cipher response: {parsed}"));
    }

    // SSH not supported — use a login item as a stand-in so tests can skip
    // gracefully rather than hard-fail.
    eprintln!(
        "Warning: SSH cipher type not supported by this Vaultwarden version \
         ({status}); substituting a login item for {name}."
    );
    create_login(
        http,
        server_url,
        access_token,
        keys,
        name,
        public_key,
        private_key,
        "",
        None,
        &[("fingerprint", fingerprint, false)],
    )
    .await
}

// ── File helpers ───────────────────────────────────────────────────────────

fn write_json(path: &std::path::Path, value: &Value, mode: u32) -> Result<()> {
    let content = serde_json::to_string_pretty(value)?;
    std::fs::write(path, &content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn write_secret_file(path: &std::path::Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ── Misc ───────────────────────────────────────────────────────────────────

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock ok")
        .as_secs() as i64
}
