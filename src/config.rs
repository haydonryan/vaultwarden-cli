use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use directories::ProjectDirs;
use keyring_core::{Entry, Error as KeyringError};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::crypto::CryptoKeys;

// ── Warning capture (for testability) ───────────────────────────────────────
//
// In production `emit_warning` writes directly to stderr via `eprintln!`.
// Tests can activate capture mode by calling `capture_warnings()`, which
// returns a RAII `WarnCapture` guard.  While the guard is live, all calls to
// `emit_warning` accumulate into an in-memory buffer instead of printing.
// When the guard is dropped, capture mode is deactivated.
//
// The static uses `Mutex<Option<_>>` so the same code path is exercised in
// both modes; there is no `#[cfg(test)]` split, which means this works
// correctly from integration tests in `tests/` (which compile the crate
// without the `test` cfg flag).

static WARN_CAPTURE: std::sync::Mutex<Option<Vec<String>>> = std::sync::Mutex::new(None);
thread_local! {
    static CONFIG_DIR_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

const ALLOW_INSECURE_KEY_FILE_ENV: &str = "VAULTWARDEN_ALLOW_INSECURE_KEY_FILE";

/// Emit a warning.  In normal operation this prints to stderr.  While a
/// [`WarnCapture`] guard is active the message is recorded in its buffer
/// instead so that tests can assert on warning output.
fn emit_warning(msg: &str) {
    let mut guard = WARN_CAPTURE.lock().expect("WARN_CAPTURE poisoned");
    if let Some(ref mut buf) = *guard {
        buf.push(msg.to_string());
    } else {
        eprintln!("{msg}");
    }
}

/// Activate warning capture mode and return a RAII guard.
///
/// While the returned [`WarnCapture`] is live, calls to [`emit_warning`]
/// accumulate into an internal buffer rather than printing to stderr.  Call
/// [`WarnCapture::drain`] to retrieve and clear the accumulated messages.
/// Dropping the guard restores normal stderr output.
///
/// Because capture is process-wide (not thread-local), callers must ensure
/// mutual exclusion — in tests, hold the `env_lock()` for the guard's
/// lifetime so parallel tests cannot interfere.
pub fn capture_warnings() -> WarnCapture {
    *WARN_CAPTURE.lock().expect("WARN_CAPTURE poisoned") = Some(Vec::new());
    WarnCapture { _private: () }
}

/// RAII guard returned by [`capture_warnings`].  Deactivates capture on drop.
pub struct WarnCapture {
    _private: (),
}

impl WarnCapture {
    /// Drain and return all warnings collected since capture was activated
    /// (or since the last `drain` call).
    pub fn drain(&self) -> Vec<String> {
        WARN_CAPTURE
            .lock()
            .expect("WARN_CAPTURE poisoned")
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }
}

impl Drop for WarnCapture {
    fn drop(&mut self) {
        *WARN_CAPTURE.lock().expect("WARN_CAPTURE poisoned") = None;
    }
}

pub struct ConfigDirOverride {
    _private: (),
}

impl Drop for ConfigDirOverride {
    fn drop(&mut self) {
        Config::clear_config_dir_override_for_process();
    }
}

// ── Secure file write ────────────────────────────────────────────────────────

/// Write `content` to `path` with owner-only (0o600) permissions,
/// eliminating the TOCTOU race that exists in the naive `fs::write` + `chmod` pattern.
///
/// ## Why the naive pattern is unsafe
///
/// `std::fs::write` opens the file with `O_CREAT | O_WRONLY | O_TRUNC` and the
/// process umask (typically `0o022`), which produces an initial mode of `0o644`.
/// A subsequent `fs::set_permissions(path, 0o600)` operates on the *path*, not
/// the file descriptor, so any process that polls the directory between the two
/// syscalls can read the file while it still has world-readable permissions.
///
/// ## How this is fixed
///
/// On Unix this function uses a three-step approach:
///
/// 1. **`open(path, O_CREAT|O_WRONLY|O_TRUNC, 0o600)`** — creates the file
///    with mode `0o600 & ~umask`. Since the umask only removes bits and the
///    group/other bits in `0o600` are already zero, the result is at most `0o600`
///    (never more permissive).
/// 2. **`fchmod(fd, 0o600)`** via `File::set_permissions` — operates on the
///    open file descriptor, not the path. This is not subject to TOCTOU and
///    guarantees exactly `0o600` regardless of the umask, before any data is
///    written.
/// 3. **`write_all(content)`** — data is written only after permissions are
///    locked. Even the brief window between steps 1 and 2 is safe because the
///    file is empty.
///
/// On non-Unix platforms this falls back to `fs::write` (permission model
/// differs; the TOCTOU concern is Unix-specific).
pub fn write_secure(path: &std::path::Path, content: impl AsRef<[u8]>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // map_err (not with_context) embeds the OS error text into a single
        // message so that err.to_string() surfaces "No such file or directory"
        // rather than only the context wrapper.  with_context would hide the
        // underlying io::Error behind a chain layer that Display does not show.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // initial creation mode (umask applied by kernel)
            .open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open {}: {e}", path.display()))?;
        // fchmod via fd — not path — ensures exactly 0o600 before any data lands
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("Failed to set permissions on {}: {e}", path.display()))?;
        file.write_all(content.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", path.display()))?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    fs::write(path, content).map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", path.display()))
}

/// Set owner-only permissions (0o700) on a directory.
///
/// Directories cannot use the fd-based approach in [`write_secure`] because
/// `mkdir` has no equivalent atomic fd + `fchmod` primitive in the standard
/// library. A briefly world-traversable directory (before this call narrows it)
/// reveals directory structure but not file *contents*, so the risk is lower
/// than for secret-bearing files. On non-Unix platforms this is a no-op.
fn set_secure_dir_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set secure permissions on {path:?}"))?;
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn set_secure_file_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set secure permissions on {path:?}"))?;
    }
    #[allow(unreachable_code)]
    Ok(())
}

fn insecure_key_file_fallback_allowed() -> bool {
    cfg!(test)
        || std::env::var(ALLOW_INSECURE_KEY_FILE_ENV)
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub server: Option<String>,
    pub client_id: Option<String>,
    pub email: Option<String>,
    // Tokens are stored in the OS keyring (or tokens.json fallback) rather
    // than config.json.  We skip *serialization* only so that pre-existing
    // config.json files that still contain these fields are transparently read
    // and can be migrated into keyring/tokens.json storage on the next save.
    // Use save_tokens() / load_saved_tokens() to persist between sessions.
    #[serde(skip_serializing, default)]
    pub access_token: Option<String>,
    #[serde(skip_serializing, default)]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing, default)]
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
    // Test and embedded callers can pin config I/O to an explicit directory
    // instead of mutating process-global HOME/XDG_CONFIG_HOME.
    #[serde(skip)]
    #[doc(hidden)]
    pub config_dir_override: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPersistenceOutcome {
    SystemKeyring,
    LegacyKeyFile,
    NotPersisted,
}

impl Config {
    pub fn config_dir() -> Result<PathBuf> {
        if let Some(path) = CONFIG_DIR_OVERRIDE.with(|override_dir| override_dir.borrow().clone()) {
            return Ok(path);
        }

        ProjectDirs::from("com", "vaultwarden", "vaultwarden-cli")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .context("Failed to determine config directory")
    }

    /// Override this thread's config directory used by static path lookups.
    ///
    /// This is intended for tests around CLI entrypoints whose production code
    /// must call [`Config::load`]. Callers must serialize use externally and
    /// call [`clear_config_dir_override_for_process`] before releasing that
    /// lock when other tests on the same thread may call static path helpers.
    pub fn set_config_dir_override_for_process(config_dir: impl Into<PathBuf>) {
        CONFIG_DIR_OVERRIDE.with(|override_dir| {
            override_dir.replace(Some(config_dir.into()));
        });
    }

    pub fn scoped_config_dir_override_for_thread(
        config_dir: impl Into<PathBuf>,
    ) -> ConfigDirOverride {
        Self::set_config_dir_override_for_process(config_dir);
        ConfigDirOverride { _private: () }
    }

    /// Clear a thread-local config directory override set by
    /// [`set_config_dir_override_for_process`].
    pub fn clear_config_dir_override_for_process() {
        CONFIG_DIR_OVERRIDE.with(|override_dir| {
            override_dir.replace(None);
        });
    }

    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.json"))
    }

    pub fn keys_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("keys.json"))
    }

    pub fn tokens_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("tokens.json"))
    }

    pub fn token_refresh_lock_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("token-refresh.lock"))
    }

    pub fn load() -> Result<Self> {
        Self::load_from_dir(Self::config_dir()?)
    }

    pub fn load_from_dir(config_dir: impl Into<PathBuf>) -> Result<Self> {
        let config_dir = config_dir.into();
        let path = config_dir.join("config.json");
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config from {path:?}"))?;
            let mut config: Self =
                serde_json::from_str(&content).context("Failed to parse config")?;
            config.config_dir_override = Some(config_dir);

            // Try to load saved keys
            if let Err(_err) = config.load_saved_keys() {
                // Saved keys are optional; ignore missing or invalid persisted state here.
            }

            // Try to load saved tokens (non-fatal: user must re-login if missing)
            if let Err(_err) = config.load_saved_tokens() {}

            Ok(config)
        } else {
            Ok(Self::default().with_config_dir(config_dir))
        }
    }

    #[must_use]
    pub fn with_config_dir(mut self, config_dir: impl Into<PathBuf>) -> Self {
        self.config_dir_override = Some(config_dir.into());
        self
    }

    fn effective_config_dir(&self) -> Result<PathBuf> {
        self.config_dir_override
            .clone()
            .map_or_else(Self::config_dir, Ok)
    }

    fn config_file_path(&self) -> Result<PathBuf> {
        Ok(self.effective_config_dir()?.join("config.json"))
    }

    fn keys_file_path(&self) -> Result<PathBuf> {
        Ok(self.effective_config_dir()?.join("keys.json"))
    }

    fn tokens_file_path(&self) -> Result<PathBuf> {
        Ok(self.effective_config_dir()?.join("tokens.json"))
    }

    pub fn token_refresh_lock_file_path(&self) -> Result<PathBuf> {
        Ok(self.effective_config_dir()?.join("token-refresh.lock"))
    }

    pub fn config_path_in(config_dir: impl AsRef<Path>) -> PathBuf {
        config_dir.as_ref().join("config.json")
    }

    pub fn keys_path_in(config_dir: impl AsRef<Path>) -> PathBuf {
        config_dir.as_ref().join("keys.json")
    }

    pub fn tokens_path_in(config_dir: impl AsRef<Path>) -> PathBuf {
        config_dir.as_ref().join("tokens.json")
    }

    pub fn save(&self) -> Result<()> {
        let path = self.config_file_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory {parent:?}"))?;
            set_secure_dir_permissions(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        // write_secure opens with O_CREAT+mode(0o600) then fchmod via fd before
        // writing, eliminating the TOCTOU race of fs::write + set_permissions.
        write_secure(&path, content.as_bytes())?;
        // Persist tokens to keyring/file whenever config is saved.
        // Tokens use #[serde(skip_serializing, default)]: not written to config.json,
        // but read back from legacy configs for migration into keyring/tokens.json.
        if self.access_token.is_some() {
            self.save_tokens()?;
        }
        Ok(())
    }

    fn keys_to_key_data(keys: &CryptoKeys) -> KeyData {
        KeyData {
            enc_key: BASE64.encode(&keys.enc_key),
            mac_key: BASE64.encode(&keys.mac_key),
        }
    }

    fn key_data_to_keys(data: KeyData) -> Result<CryptoKeys> {
        Ok(CryptoKeys {
            enc_key: BASE64.decode(&data.enc_key)?,
            mac_key: BASE64.decode(&data.mac_key)?,
        })
    }

    pub fn save_keys(&self) -> Result<KeyPersistenceOutcome> {
        // Store keys in the OS keyring instead of a plaintext file.
        // If keyring is unavailable, default to no-persist rather than writing
        // decrypted keys to disk. A plaintext file fallback exists only behind
        // an explicit unsafe compatibility/test opt-in.
        let user_keys = self.crypto_keys.as_ref().map(Self::keys_to_key_data);
        let org_keys: HashMap<String, KeyData> = self
            .org_crypto_keys
            .iter()
            .map(|(id, keys)| (id.clone(), Self::keys_to_key_data(keys)))
            .collect();

        let saved = SavedKeys {
            user_keys,
            org_keys,
        };
        let content = serde_json::to_string(&saved)?;

        // Stage 1: determine whether we can even attempt the keyring.
        //
        // `client_id` is used as the keyring account name.  If it is absent
        // (e.g. incomplete login, manually edited config) we cannot construct
        // a stable keyring key and must fall back to file storage.  This is
        // a security degradation, so we warn explicitly rather than silently
        // downgrading.
        let keyring_entry = match &self.client_id {
            None => {
                emit_warning("Warning: client_id is not set — cannot use the system keyring.");
                None
            }
            Some(client_id) => match keyring_entry_for_keys(client_id) {
                Ok(entry) => Some(entry),
                Err(err) => {
                    emit_warning(&format!(
                        "Warning: Could not create keyring entry: {err}. \
                         Key persistence will be disabled unless insecure file fallback is explicitly enabled.",
                    ));
                    None
                }
            },
        };

        // Stage 2: write to the keyring if we have an entry; otherwise file.
        if let Some(entry) = keyring_entry {
            match entry.set_password(&content) {
                Ok(()) => {
                    // Remove legacy keys.json if it exists
                    let path = self.keys_file_path()?;
                    if path.exists() {
                        drop(fs::remove_file(&path));
                    }
                    return Ok(KeyPersistenceOutcome::SystemKeyring);
                }
                Err(err) => {
                    emit_warning(&format!(
                        "Warning: Could not store keys in system keyring: {err}. \
                         Key persistence will be disabled unless insecure file fallback is explicitly enabled.",
                    ));
                }
            }
        }

        let path = self.keys_file_path()?;
        if !insecure_key_file_fallback_allowed() {
            if path.exists() {
                drop(fs::remove_file(&path));
            }
            emit_warning(&format!(
                "Warning: Vault keys were not persisted. Unlock state is memory-only because \
                 the system keyring is unavailable. To use the legacy plaintext keys.json \
                 fallback, set {ALLOW_INSECURE_KEY_FILE_ENV}=true."
            ));
            return Ok(KeyPersistenceOutcome::NotPersisted);
        }

        emit_warning(&format!(
            "Warning: {ALLOW_INSECURE_KEY_FILE_ENV}=true enables legacy plaintext keys.json \
             storage. keys.json is owner-only but decrypted vault keys are not encrypted at rest."
        ));

        // Explicit insecure file fallback — reached from all three keyring failure paths:
        //   • client_id is None
        //   • keyring entry creation failed
        //   • keyring set_password failed
        // write_secure uses fchmod-via-fd to avoid the TOCTOU race.
        write_secure(&path, content.as_bytes())?;
        Ok(KeyPersistenceOutcome::LegacyKeyFile)
    }

    pub fn load_saved_keys(&mut self) -> Result<()> {
        // Try OS keyring first
        if let Some(client_id) = &self.client_id
            && let Ok(entry) = keyring_entry_for_keys(client_id)
            && let Ok(content) = entry.get_password()
        {
            let saved: SavedKeys = serde_json::from_str(&content)?;
            if let Some(keys_data) = saved.user_keys {
                self.crypto_keys = Some(Self::key_data_to_keys(keys_data)?);
            }
            for (id, keys_data) in saved.org_keys {
                self.org_crypto_keys
                    .insert(id, Self::key_data_to_keys(keys_data)?);
            }
            return Ok(());
        }

        // Fallback: read from file (legacy)
        let path = self.keys_file_path()?;
        if path.exists() {
            if !insecure_key_file_fallback_allowed() {
                drop(fs::remove_file(&path));
                emit_warning(&format!(
                    "Warning: Ignored and removed legacy plaintext keys.json. Unlock again with \
                     system keyring support, or set {ALLOW_INSECURE_KEY_FILE_ENV}=true to accept \
                     the insecure file fallback."
                ));
                return Ok(());
            }
            set_secure_file_permissions(&path)?;
            let content = fs::read_to_string(&path)?;
            let saved: SavedKeys = serde_json::from_str(&content)?;

            if let Some(keys_data) = saved.user_keys {
                self.crypto_keys = Some(Self::key_data_to_keys(keys_data)?);
            }

            for (id, keys_data) in saved.org_keys {
                self.org_crypto_keys
                    .insert(id, Self::key_data_to_keys(keys_data)?);
            }
        }
        Ok(())
    }

    pub fn delete_saved_keys(&self) -> Result<()> {
        // Delete from OS keyring
        if let Some(client_id) = &self.client_id
            && let Some(entry) = optional_keyring_entry_for_delete(
                keyring_entry_for_keys(client_id),
                "saved vault keys",
            )?
        {
            delete_keyring_credential(entry, "saved vault keys")?;
        }

        // Also remove legacy keys.json if it exists
        let path = self.keys_file_path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    pub fn save_tokens(&self) -> Result<()> {
        let access_token = match &self.access_token {
            None => return Ok(()), // nothing to persist
            Some(t) => t.clone(),
        };
        let saved = SavedTokens {
            access_token,
            refresh_token: self.refresh_token.clone(),
            token_expiry: self.token_expiry,
        };
        let content = serde_json::to_string(&saved)?;

        // Stage 1: determine whether we can attempt the keyring.
        // `client_id` is used as the keyring account discriminator.
        let keyring_entry = match &self.client_id {
            None => {
                emit_warning(
                    "Warning: client_id is not set — tokens will be stored in a \
                     file instead of the system keyring (less secure).",
                );
                None
            }
            Some(client_id) => match keyring_entry_for_tokens(client_id) {
                Ok(entry) => Some(entry),
                Err(err) => {
                    emit_warning(&format!(
                        "Warning: Could not create keyring entry for tokens: {err}. \
                         Falling back to file-based token storage (less secure).",
                    ));
                    None
                }
            },
        };

        // Stage 2: write to keyring if available; otherwise file.
        if let Some(entry) = keyring_entry {
            match entry.set_password(&content) {
                Ok(()) => {
                    // Remove tokens.json if it exists (keyring is now authoritative)
                    let path = self.tokens_file_path()?;
                    if path.exists() {
                        drop(fs::remove_file(&path));
                    }
                    return Ok(());
                }
                Err(err) => {
                    emit_warning(&format!(
                        "Warning: Could not store tokens in system keyring: {err}. \
                         Falling back to file-based token storage (less secure).",
                    ));
                }
            }
        }

        // File fallback — write_secure uses fchmod-via-fd to avoid the TOCTOU race.
        let path = self.tokens_file_path()?;
        write_secure(&path, content.as_bytes())?;
        Ok(())
    }

    pub fn load_saved_tokens(&mut self) -> Result<()> {
        // Try OS keyring first
        if let Some(client_id) = &self.client_id
            && let Ok(entry) = keyring_entry_for_tokens(client_id)
            && let Ok(content) = entry.get_password()
        {
            let saved: SavedTokens = serde_json::from_str(&content)?;
            self.access_token = Some(saved.access_token);
            self.refresh_token = saved.refresh_token;
            self.token_expiry = saved.token_expiry;
            return Ok(());
        }

        // Fallback: read from file
        let path = self.tokens_file_path()?;
        if path.exists() {
            set_secure_file_permissions(&path)?;
            let content = fs::read_to_string(&path)?;
            let saved: SavedTokens = serde_json::from_str(&content)?;
            self.access_token = Some(saved.access_token);
            self.refresh_token = saved.refresh_token;
            self.token_expiry = saved.token_expiry;
        }
        Ok(())
    }

    pub fn delete_saved_tokens(&self) -> Result<()> {
        // Delete from OS keyring
        if let Some(client_id) = &self.client_id
            && let Some(entry) = optional_keyring_entry_for_delete(
                keyring_entry_for_tokens(client_id),
                "saved tokens",
            )?
        {
            delete_keyring_credential(entry, "saved tokens")?;
        }

        // Also remove tokens.json if it exists
        let path = self.tokens_file_path()?;
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
        self.delete_saved_tokens()?;
        self.save()
    }

    #[must_use]
    pub fn get_keys_for_cipher(&self, org_id: Option<&str>) -> Option<&CryptoKeys> {
        if let Some(org_id) = org_id {
            self.org_crypto_keys.get(org_id)
        } else {
            self.crypto_keys.as_ref()
        }
    }

    #[must_use]
    pub const fn is_logged_in(&self) -> bool {
        self.access_token.is_some() && self.server.is_some()
    }

    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.crypto_keys.is_some()
    }

    #[must_use]
    pub fn get_server(&self) -> Option<&str> {
        self.server.as_deref()
    }
}

#[derive(Serialize, Deserialize)]
struct KeyData {
    enc_key: String,
    mac_key: String,
}

#[derive(Serialize, Deserialize)]
struct SavedTokens {
    access_token: String,
    refresh_token: Option<String>,
    token_expiry: Option<i64>,
}

#[derive(Serialize, Deserialize, Default)]
struct SavedKeys {
    user_keys: Option<KeyData>,
    #[serde(default)]
    org_keys: HashMap<String, KeyData>,
}

fn keyring_entry(client_id: &str) -> Result<Entry> {
    Ok(Entry::new("vaultwarden-cli", client_id)?)
}

fn keyring_entry_for_keys(client_id: &str) -> Result<Entry> {
    Ok(Entry::new("vaultwarden-cli", &format!("{client_id}:keys"))?)
}

fn keyring_entry_for_tokens(client_id: &str) -> Result<Entry> {
    Ok(Entry::new(
        "vaultwarden-cli",
        &format!("{client_id}:tokens"),
    )?)
}

fn optional_keyring_entry_for_delete(entry: Result<Entry>, label: &str) -> Result<Option<Entry>> {
    match entry {
        Ok(entry) => Ok(Some(entry)),
        Err(err) => {
            if err
                .downcast_ref::<KeyringError>()
                .is_some_and(|err| matches!(err, KeyringError::NoEntry))
            {
                Ok(None)
            } else {
                Err(err).with_context(|| format!("Failed to access {label} in system keyring"))
            }
        }
    }
}

fn delete_keyring_credential(entry: Entry, label: &str) -> Result<()> {
    match entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to delete {label} from system keyring"))
        }
    }
}

// Store client secret securely using keyring
pub fn store_client_secret(client_id: &str, secret: &str) -> Result<()> {
    keyring_entry(client_id)?.set_password(secret)?;
    Ok(())
}

pub fn get_client_secret(client_id: &str) -> Result<String> {
    keyring_entry(client_id)?
        .get_password()
        .context("Client secret not found")
}

pub fn delete_client_secret(client_id: &str) -> Result<()> {
    if let Some(entry) =
        optional_keyring_entry_for_delete(keyring_entry(client_id), "client secret")?
    {
        delete_keyring_credential(entry, "client secret")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeyring {
        previous: Option<std::sync::Arc<keyring_core::CredentialStore>>,
    }

    impl MockKeyring {
        fn install() -> Self {
            let previous = keyring_core::unset_default_store();
            keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
            Self { previous }
        }
    }

    impl Drop for MockKeyring {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                keyring_core::set_default_store(previous);
            } else {
                keyring_core::unset_default_store();
            }
        }
    }

    fn mock_entry(user: &str) -> Entry {
        Entry::new("vaultwarden-cli", user).expect("mock keyring entry should be created")
    }

    fn fail_next_keyring_call(entry: &Entry) {
        let mock = entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .expect("entry should come from mock keyring");
        mock.set_error(KeyringError::Invalid(
            "delete".to_string(),
            "simulated failure".to_string(),
        ));
    }

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

    mod keyring_delete_tests {
        use super::*;

        #[test]
        fn delete_saved_keys_ignores_missing_keyring_entry() {
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let config = Config {
                client_id: Some("client-keys-missing".to_string()),
                ..Default::default()
            };

            config
                .delete_saved_keys()
                .expect("missing keyring keys should be idempotent");
        }

        #[test]
        fn delete_saved_keys_reports_keyring_delete_failure() {
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let entry = mock_entry("client-keys-fail:keys");
            entry.set_password("saved keys").unwrap();
            fail_next_keyring_call(&entry);

            let config = Config {
                client_id: Some("client-keys-fail".to_string()),
                ..Default::default()
            };

            let err = config
                .delete_saved_keys()
                .expect_err("keyring delete failure should be reported");

            assert!(
                err.to_string()
                    .contains("Failed to delete saved vault keys from system keyring"),
                "unexpected error: {err:#}"
            );
        }

        #[test]
        fn delete_saved_tokens_reports_keyring_delete_failure() {
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let entry = mock_entry("client-tokens-fail:tokens");
            entry.set_password("saved tokens").unwrap();
            fail_next_keyring_call(&entry);

            let config = Config {
                client_id: Some("client-tokens-fail".to_string()),
                ..Default::default()
            };

            let err = config
                .delete_saved_tokens()
                .expect_err("keyring token delete failure should be reported");

            assert!(
                err.to_string()
                    .contains("Failed to delete saved tokens from system keyring"),
                "unexpected error: {err:#}"
            );
        }

        #[test]
        fn delete_client_secret_ignores_missing_keyring_entry() {
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();

            delete_client_secret("client-secret-missing")
                .expect("missing client secret should be idempotent");
        }

        #[test]
        fn delete_client_secret_reports_keyring_delete_failure() {
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let entry = mock_entry("client-secret-fail");
            entry.set_password("client secret").unwrap();
            fail_next_keyring_call(&entry);

            let err = delete_client_secret("client-secret-fail")
                .expect_err("client secret delete failure should be reported");

            assert!(
                err.to_string()
                    .contains("Failed to delete client secret from system keyring"),
                "unexpected error: {err:#}"
            );
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
            // access_token, refresh_token, and token_expiry use
            // #[serde(skip_serializing, default)]: they are NOT written to
            // config.json but ARE read back from legacy configs that still
            // contain them.  This lets upgrade code detect and migrate old
            // tokens into keyring / tokens.json storage.
            let json = r#"{
                "server": "https://vault.example.com",
                "client_id": "user.client-123",
                "email": "user@example.com",
                "access_token": "test-token",
                "refresh_token": "test-refresh",
                "token_expiry": 1234567890,
                "kdf_iterations": 600000
            }"#;

            let config: Config = serde_json::from_str(json).unwrap();
            assert_eq!(config.server, Some("https://vault.example.com".to_string()));
            assert_eq!(config.client_id, Some("user.client-123".to_string()));
            assert_eq!(config.email, Some("user@example.com".to_string()));
            assert_eq!(config.kdf_iterations, Some(600000));
            // Legacy token values present in JSON are deserialized so callers
            // can detect and migrate them into keyring / tokens.json.
            assert_eq!(config.access_token, Some("test-token".to_string()));
            assert_eq!(config.refresh_token, Some("test-refresh".to_string()));
            assert_eq!(config.token_expiry, Some(1234567890));
            // Pure in-memory fields are never present in JSON.
            assert!(config.crypto_keys.is_none());
        }

        #[test]
        fn test_config_serialization_excludes_tokens() {
            // Tokens held in memory must NOT be written back to config.json;
            // they are persisted separately via keyring / tokens.json.
            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("secret-access".to_string()),
                refresh_token: Some("secret-refresh".to_string()),
                token_expiry: Some(9999999999),
                ..Default::default()
            };

            let json = serde_json::to_string(&config).unwrap();

            assert!(
                !json.contains("access_token"),
                "access_token must not appear in config.json"
            );
            assert!(
                !json.contains("refresh_token"),
                "refresh_token must not appear in config.json"
            );
            assert!(
                !json.contains("token_expiry"),
                "token_expiry must not appear in config.json"
            );
            assert!(
                !json.contains("secret-access"),
                "token value must not appear in config.json"
            );
            assert!(json.contains("vault.example.com"));
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
                enc_key: BASE64.encode(&keys.enc_key),
                mac_key: BASE64.encode(&keys.mac_key),
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
            let enc_key = BASE64.decode(&keys_data.enc_key).unwrap();
            let mac_key = BASE64.decode(&keys_data.mac_key).unwrap();

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
                            enc_key: BASE64.encode(&keys.enc_key),
                            mac_key: BASE64.encode(&keys.mac_key),
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

            let org1_data = &loaded_saved.org_keys["org-1"];
            let org1_enc = BASE64.decode(&org1_data.enc_key).unwrap();
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
