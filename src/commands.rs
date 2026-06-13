use anyhow::{Context, Result};
use fs4::FileExt as Fs4FileExt;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::process::{Command, ExitStatus};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn system_time_to_unix_seconds(time: SystemTime) -> Result<i64> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?;
    i64::try_from(duration.as_secs()).context("System time exceeds supported Unix timestamp range")
}

fn unix_now() -> Result<i64> {
    system_time_to_unix_seconds(SystemTime::now())
}

fn token_expiry_from_lifetime(now: i64, expires_in: i64) -> Result<i64> {
    if expires_in <= 0 {
        anyhow::bail!("Server returned invalid token lifetime: expires_in must be positive");
    }

    now.checked_add(expires_in)
        .context("Server returned invalid token lifetime: expires_in is too large")
}

use crate::api::ApiClient;
use crate::config::{self, Config, KeyPersistenceOutcome};
use crate::crypto::CryptoKeys;
use crate::models::{Cipher, CipherOutput, CipherType, FieldOutput};

struct TokenRefreshLock {
    file: File,
}

impl Drop for TokenRefreshLock {
    fn drop(&mut self) {
        drop(Fs4FileExt::unlock(&self.file));
    }
}

async fn acquire_token_refresh_lock(config: &Config) -> Result<TokenRefreshLock> {
    let path = config.token_refresh_lock_file_path()?;
    tokio::task::spawn_blocking(move || acquire_token_refresh_lock_blocking(path))
        .await
        .context("Token refresh lock task failed")?
}

fn acquire_token_refresh_lock_blocking(path: std::path::PathBuf) -> Result<TokenRefreshLock> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory {parent:?}"))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("Failed to open token refresh lock at {}", path.display()))?;
    Fs4FileExt::lock(&file)
        .with_context(|| format!("Failed to lock token refresh state at {}", path.display()))?;
    Ok(TokenRefreshLock { file })
}

/// Options controlling connection behaviour for commands that talk to Vaultwarden.
///
/// The [`Default`] implementation preserves the original secure-only behaviour
/// (HTTPS required). Callers that only need to set one field can use struct-update
/// syntax: `CommandOptions { allow_insecure_http: true, ..Default::default() }`.
#[derive(Debug, Default, Clone)]
pub struct CommandOptions {
    /// Permit `http://` server URLs. Has the same effect as
    /// `VAULTWARDEN_ALLOW_HTTP=1` but takes precedence over it.
    /// Defaults to `false`.
    pub allow_insecure_http: bool,

    /// Permit plaintext JSON output when stdout is not a terminal.
    /// JSON output includes decrypted secret fields and is otherwise rejected
    /// for non-interactive stdout to avoid accidental capture.
    pub allow_plaintext_json: bool,

    /// Whether stdout should be treated as an interactive terminal for
    /// plaintext JSON output policy.
    pub json_stdout_is_terminal: bool,
}

#[derive(Debug)]
pub enum CommandOutcome {
    Success,
    ChildExit(ExitStatus),
}

impl CommandOutcome {
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::ChildExit(status) => status.code().unwrap_or(1),
        }
    }
}

impl CommandOptions {
    #[must_use]
    pub fn for_cli(allow_insecure_http: bool, allow_plaintext_json: bool) -> Self {
        Self {
            allow_insecure_http,
            allow_plaintext_json,
            json_stdout_is_terminal: io::stdout().is_terminal(),
        }
    }
}

fn ensure_plaintext_json_allowed(opts: &CommandOptions) -> Result<()> {
    if opts.allow_plaintext_json || opts.json_stdout_is_terminal {
        return Ok(());
    }

    anyhow::bail!(
        "Plaintext JSON output includes decrypted secrets and is blocked when stdout is not a terminal. Pass --allow-plaintext-json or set VAULTWARDEN_ALLOW_PLAINTEXT_JSON=true to intentionally allow capture."
    )
}

pub async fn login(
    server: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    opts: &CommandOptions,
) -> Result<()> {
    let mut config = Config::load()?;

    // Use provided values or existing config
    let server = server
        .or_else(|| config.server.clone())
        .context("Server URL is required. Use --server or set it previously.")?;
    let client_id = client_id
        .or_else(|| config.client_id.clone())
        .context("Client ID is required. Use --client-id.")?;
    let client_secret = client_secret
        .or_else(|| config::get_client_secret(&client_id).ok())
        .context("Client secret is required. Use --client-secret.")?;

    let api = ApiClient::new_with_flags(&server, opts.allow_insecure_http)?;

    // Check server is reachable
    println!("Connecting to {server}...");
    if !api.check_server().await? {
        anyhow::bail!("Server is not reachable");
    }

    // Perform login
    println!("Authenticating...");
    let token_response = api.login(&client_id, &client_secret).await?;

    // Calculate token expiry
    let expiry = token_expiry_from_lifetime(unix_now()?, token_response.expires_in)?;

    // Stage configuration in memory. Persist only after the post-login sync
    // succeeds, so a token success followed by sync failure cannot leave a
    // partially logged-in session on disk.
    config.server = Some(server);
    config.client_id = Some(client_id.clone());
    config.access_token = Some(token_response.access_token.clone());
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(expiry);
    config.encrypted_key = token_response.key;
    config.kdf_iterations = token_response.kdf_iterations;

    // Fetch profile to get email for key derivation
    let sync_response = api.sync(&token_response.access_token).await?;
    config.email = Some(sync_response.profile.email.clone());
    config.encrypted_private_key = sync_response.profile.private_key.clone();

    // Store organization keys
    config.org_keys.clear();
    for org in &sync_response.profile.organizations {
        if let Some(key) = &org.key {
            config.org_keys.insert(org.id.clone(), key.clone());
        }
    }
    config.save()?;

    // Best-effort secure storage: some environments (headless/minimal Linux) don't provide
    // an activatable secret service over D-Bus.
    if let Err(err) = config::store_client_secret(&client_id, &client_secret) {
        eprintln!("Warning: Could not store client secret in system keyring: {err}");
        eprintln!(
            "You can keep using this session. If you need to login again later, pass --client-secret."
        );
    }

    println!("Login successful!");
    let org_count = config.org_keys.len();
    if org_count > 0 {
        println!("Found {org_count} organization(s).");
    }
    println!("Run 'vaultwarden-cli unlock' to unlock the vault with your master password.");
    Ok(())
}

pub async fn unlock(password: Option<String>, opts: &CommandOptions) -> Result<()> {
    let mut config = Config::load()?;

    if !config.is_logged_in() {
        anyhow::bail!("Not logged in. Please run 'vaultwarden-cli login' first.");
    }

    // Ensure token is still valid before prompting for password
    ensure_valid_token(&mut config, opts.allow_insecure_http).await?;

    let email = config
        .email
        .as_ref()
        .context("Email not found. Please login again.")?;
    let encrypted_key = config
        .encrypted_key
        .as_ref()
        .context("Encrypted key not found. Please login again.")?;
    let iterations = config.kdf_iterations.unwrap_or(600000);

    // Get password - either from argument or prompt
    let password = if let Some(p) = password {
        p
    } else {
        print!("Master password: ");
        io::stdout().flush()?;
        rpassword::read_password()?
    };

    println!("Deriving key...");

    // Derive master key from password and email
    let master_key = CryptoKeys::derive_master_key(&password, email, iterations);

    // Decrypt the symmetric key
    let crypto_keys = CryptoKeys::decrypt_symmetric_key(&master_key, encrypted_key)
        .context("Failed to decrypt vault key. Check your master password.")?;

    // Decrypt organization keys if present
    if let Some(encrypted_private_key) = &config.encrypted_private_key {
        println!("Decrypting organization keys...");

        // Decrypt RSA private key
        match crypto_keys.decrypt_private_key(encrypted_private_key) {
            Ok(private_key) => {
                // Decrypt each organization's key
                for (org_id, encrypted_org_key) in &config.org_keys {
                    match CryptoKeys::decrypt_org_key(encrypted_org_key, &private_key) {
                        Ok(org_keys) => {
                            config.org_crypto_keys.insert(org_id.clone(), org_keys);
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to decrypt org {org_id} key: {e}");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to decrypt private key: {e}");
            }
        }
    }

    // Save the keys
    config.crypto_keys = Some(crypto_keys);
    let key_persistence = config.save_keys()?;
    if key_persistence == KeyPersistenceOutcome::NotPersisted {
        anyhow::bail!(
            "Vault keys were not persisted. Unlock cannot create a reusable unlocked session \
             because the system keyring is unavailable and VAULTWARDEN_ALLOW_INSECURE_KEY_FILE \
             is not set."
        );
    }

    let org_count = config.org_crypto_keys.len();
    if org_count > 0 {
        println!("Vault unlocked successfully! ({org_count} organization keys decrypted)");
    } else {
        println!("Vault unlocked successfully!");
    }
    Ok(())
}

pub async fn lock() -> Result<()> {
    let config = Config::load()?;
    lock_loaded_config(&config)?;
    Ok(())
}

fn lock_loaded_config(config: &Config) -> Result<()> {
    config.delete_saved_keys()?;
    println!("Vault locked.");
    Ok(())
}

pub async fn logout() -> Result<()> {
    logout_loaded_config(Config::load()?)
}

fn logout_loaded_config(mut config: Config) -> Result<()> {
    if !config.is_logged_in() {
        println!("Not currently logged in.");
        return Ok(());
    }

    // Delete stored client secret
    if let Some(client_id) = &config.client_id {
        config::delete_client_secret(client_id)?;
    }

    config.clear()?;
    println!("Logged out successfully.");
    Ok(())
}

pub async fn status() -> Result<()> {
    let config = Config::load()?;

    if !config.is_logged_in() {
        println!("Status: Not logged in");
        return Ok(());
    }

    println!("Status: Logged in");
    if let Some(server) = &config.server {
        println!("Server: {server}");
    }
    if let Some(client_id) = &config.client_id {
        println!("Client ID: {client_id}");
    }
    if let Some(email) = &config.email {
        println!("Email: {email}");
    }

    // Check token expiry
    if let Some(expiry) = config.token_expiry {
        let now = unix_now()?;
        if expiry > now {
            let remaining = expiry - now;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            println!("Token expires in: {hours}h {minutes}m");
        } else {
            println!("Token: Expired (will refresh on next request)");
        }
    }

    if config.is_unlocked() {
        println!("Vault: Unlocked");
    } else {
        println!("Vault: Locked");
    }

    Ok(())
}

async fn ensure_valid_token(config: &mut Config, allow_insecure_http: bool) -> Result<String> {
    if !token_needs_refresh(config)? {
        return config
            .access_token
            .clone()
            .context("Not logged in. Please run 'vaultwarden-cli login' first.");
    }

    let _lock = acquire_token_refresh_lock(config).await?;
    config.load_saved_tokens()?;

    if !token_needs_refresh(config)? {
        return config
            .access_token
            .clone()
            .context("Not logged in. Please run 'vaultwarden-cli login' first.");
    }

    let refresh_token = config
        .refresh_token
        .clone()
        .context("Token expired. Please login again.")?;
    let api = ApiClient::from_config_with_flags(config, allow_insecure_http)?;
    let token_response = api
        .refresh_token(&refresh_token)
        .await
        .context("Token expired and refresh failed. Please login again.")?;
    let new_expiry = token_expiry_from_lifetime(unix_now()?, token_response.expires_in)?;
    config.access_token = Some(token_response.access_token.clone());
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(new_expiry);
    config.save()?;
    Ok(token_response.access_token)
}

fn token_needs_refresh(config: &Config) -> Result<bool> {
    let Some(expiry) = config.token_expiry else {
        return Ok(false);
    };
    Ok(unix_now()? >= expiry.saturating_sub(60))
}

fn ensure_unlocked(config: &Config) -> Result<()> {
    if config.crypto_keys.is_none() {
        anyhow::bail!("Vault is locked. Please run 'vaultwarden-cli unlock' first.");
    }
    Ok(())
}

struct SyncContext {
    config: Config,
    access_token: String,
    api: ApiClient,
    sync_response: crate::models::SyncResponse,
}

struct ApiContext {
    config: Config,
    access_token: String,
    api: ApiClient,
}

async fn load_api_context(allow_insecure_http: bool) -> Result<ApiContext> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config, allow_insecure_http).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config_with_flags(&config, allow_insecure_http)?;
    Ok(ApiContext {
        config,
        access_token,
        api,
    })
}

async fn load_sync_context(allow_insecure_http: bool) -> Result<SyncContext> {
    let ctx = load_api_context(allow_insecure_http).await?;
    let sync_response = ctx.api.sync(&ctx.access_token).await?;
    Ok(SyncContext {
        config: ctx.config,
        access_token: ctx.access_token,
        api: ctx.api,
        sync_response,
    })
}

fn resolve_org_and_collection_filters(
    sync_response: &crate::models::SyncResponse,
    config: &Config,
    org_filter: Option<&str>,
    collection_filter: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let org_id_filter = org_filter
        .map(|org| resolve_org_id(&sync_response.profile, org))
        .transpose()?;
    let collection_id_filter = collection_filter
        .map(|col| {
            resolve_collection_id(
                &sync_response.collections,
                col,
                org_id_filter.as_deref(),
                config,
            )
        })
        .transpose()?;
    Ok((org_id_filter, collection_id_filter))
}

fn cipher_matches_filters(
    cipher: &Cipher,
    org_id_filter: Option<&str>,
    collection_id_filter: Option<&str>,
    folder_id_filter: Option<&str>,
) -> bool {
    if let Some(oid) = org_id_filter
        && cipher.organization_id.as_deref() != Some(oid)
    {
        return false;
    }
    if let Some(fid) = folder_id_filter
        && cipher.folder_id.as_deref() != Some(fid)
    {
        return false;
    }
    if let Some(cid) = collection_id_filter
        && !cipher.collection_ids.iter().any(|id| id == cid)
    {
        return false;
    }
    true
}

fn find_cipher_output(
    ciphers: &[Cipher],
    config: &Config,
    mut predicate: impl FnMut(&CipherOutput) -> bool,
    matches_filters: impl Fn(&Cipher) -> bool,
) -> Option<CipherOutput> {
    for cipher in ciphers {
        if !matches_filters(cipher) {
            continue;
        }
        let keys = match get_cipher_keys(config, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(output) = decrypt_cipher(cipher, keys)
            && predicate(&output)
        {
            return Some(output);
        }
    }
    None
}

fn ambiguous_item_name_message(raw_name: &str, count: usize) -> String {
    format!(
        "item name '{raw_name}' is ambiguous; {count} vault items match case-insensitively. Use an item id to disambiguate."
    )
}

fn find_cipher_output_by_name_or_id(
    ciphers: &[Cipher],
    config: &Config,
    name_or_id: &str,
    matches_filters: impl Fn(&Cipher) -> bool,
    profile: CipherDecryptionProfile,
) -> Result<CipherOutput> {
    if let Some(cipher) = ciphers
        .iter()
        .find(|c| c.id == name_or_id && matches_filters(c))
    {
        let keys = get_cipher_keys(config, cipher)?;
        return decrypt_cipher_with_profile(cipher, keys, profile);
    }

    let name_lower = name_or_id.to_lowercase();
    let mut matching_ciphers = Vec::new();
    for cipher in ciphers {
        if !matches_filters(cipher) {
            continue;
        }
        let keys = match get_cipher_keys(config, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(output) =
            decrypt_cipher_with_profile(cipher, keys, CipherDecryptionProfile::list_env_names())
            && output.name.to_lowercase() == name_lower
        {
            matching_ciphers.push(cipher);
        }
    }

    match matching_ciphers.as_slice() {
        [cipher] => {
            let keys = get_cipher_keys(config, cipher)?;
            decrypt_cipher_with_profile(cipher, keys, profile)
        }
        [] => anyhow::bail!("Item '{name_or_id}' not found"),
        matches => anyhow::bail!("{}", ambiguous_item_name_message(name_or_id, matches.len())),
    }
}

async fn fetch_cipher_output_by_id(
    api_ctx: &ApiContext,
    cipher_id: &str,
    profile: CipherDecryptionProfile,
) -> Result<CipherOutput> {
    let cipher = api_ctx
        .api
        .cipher_by_id(&api_ctx.access_token, cipher_id)
        .await?;
    let keys = get_cipher_keys(&api_ctx.config, &cipher)?;
    decrypt_cipher_with_profile(&cipher, keys, profile)
}

#[allow(clippy::too_many_arguments)]
async fn fetch_filtered_cipher_outputs(
    api: &ApiClient,
    access_token: &str,
    config: &Config,
    org_id_filter: Option<&str>,
    collection_id_filter: Option<&str>,
    type_filter: Option<CipherType>,
    folder_id_filter: Option<&str>,
    profile: CipherDecryptionProfile,
) -> Result<Vec<CipherOutput>> {
    let cipher_type = type_filter.map(|value| value as u8);
    let cipher_list = api
        .ciphers_filtered(
            access_token,
            org_id_filter,
            collection_id_filter,
            cipher_type,
        )
        .await?;
    let mut outputs = Vec::new();
    let mut failures = Vec::new();
    for cipher in cipher_list.data.iter().filter(|cipher| {
        cipher_matches_filters(
            cipher,
            org_id_filter,
            collection_id_filter,
            folder_id_filter,
        )
    }) {
        let output = get_cipher_keys(config, cipher)
            .and_then(|keys| decrypt_cipher_with_profile(cipher, keys, profile))
            .with_context(|| {
                format!(
                    "selected filtered item '{}' could not be decrypted",
                    cipher.id
                )
            });
        match output {
            Ok(output) => outputs.push(output),
            Err(err) => failures.push(format!("{}: {err:#}", cipher.id)),
        }
    }

    if !failures.is_empty() {
        anyhow::bail!(
            "filtered run could not decrypt {} selected item(s): {}",
            failures.len(),
            failures.join("; ")
        );
    }

    Ok(outputs)
}

fn get_cipher_keys<'a>(config: &'a Config, cipher: &Cipher) -> Result<&'a CryptoKeys> {
    if let Some(keys) = config.get_keys_for_cipher(cipher.organization_id.as_deref()) {
        Ok(keys)
    } else {
        if let Some(org_id) = &cipher.organization_id {
            anyhow::bail!("Organization key not available for org {org_id}. Try re-logging in.");
        }
        anyhow::bail!("No decryption keys available");
    }
}

fn try_decrypt(keys: &CryptoKeys, encrypted: Option<&str>) -> Result<Option<String>> {
    encrypted.map(|e| keys.decrypt_to_string(e)).transpose()
}

fn try_decrypt_cipher_subfield(
    keys: &CryptoKeys,
    encrypted: Option<&str>,
    cipher_id: &str,
    field_name: &str,
) -> Result<Option<String>> {
    encrypted
        .map(|value| {
            keys.decrypt_to_string(value)
                .with_context(|| format!("failed to decrypt {field_name} for cipher {cipher_id}"))
        })
        .transpose()
}

fn decrypt_cipher(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    decrypt_cipher_with_profile(cipher, keys, CipherDecryptionProfile::full())
}

#[derive(Debug, Clone, Copy)]
struct CipherDecryptionProfile {
    username: bool,
    password: bool,
    uri: bool,
    notes: bool,
    field_names: bool,
    field_values: bool,
    ssh_public_key: bool,
    ssh_private_key: bool,
    ssh_fingerprint: bool,
    decrypt_present_standard_values: bool,
}

impl CipherDecryptionProfile {
    const fn full() -> Self {
        Self {
            username: true,
            password: true,
            uri: true,
            notes: true,
            field_names: true,
            field_values: true,
            ssh_public_key: true,
            ssh_private_key: true,
            ssh_fingerprint: true,
            decrypt_present_standard_values: true,
        }
    }

    const fn run_env() -> Self {
        Self {
            username: true,
            password: true,
            uri: false,
            notes: false,
            field_names: false,
            field_values: false,
            ssh_public_key: false,
            ssh_private_key: false,
            ssh_fingerprint: false,
            decrypt_present_standard_values: true,
        }
    }

    const fn list_env_names() -> Self {
        Self {
            username: true,
            password: true,
            uri: true,
            notes: false,
            field_names: true,
            field_values: false,
            ssh_public_key: true,
            ssh_private_key: true,
            ssh_fingerprint: true,
            decrypt_present_standard_values: false,
        }
    }

    const fn interpolation(component: &str) -> Self {
        let component = component.as_bytes();
        Self {
            username: matches!(component, b"username"),
            password: matches!(component, b"password"),
            uri: matches!(component, b"uri"),
            notes: matches!(component, b"notes" | b"note"),
            field_names: true,
            field_values: true,
            ssh_public_key: matches!(component, b"ssh_public_key" | b"public_key" | b"publickey"),
            ssh_private_key: matches!(
                component,
                b"ssh_private_key" | b"private_key" | b"privatekey"
            ),
            ssh_fingerprint: matches!(component, b"ssh_fingerprint" | b"fingerprint"),
            decrypt_present_standard_values: true,
        }
    }
}

fn decrypt_optional_cipher_value(
    keys: &CryptoKeys,
    encrypted: Option<&str>,
    should_include: bool,
    should_decrypt: bool,
) -> Result<Option<String>> {
    if !should_include {
        return Ok(None);
    }
    if should_decrypt {
        try_decrypt(keys, encrypted)
    } else {
        Ok(encrypted.map(|_| String::new()))
    }
}

fn decrypt_optional_cipher_subfield(
    keys: &CryptoKeys,
    encrypted: Option<&str>,
    cipher_id: &str,
    field_name: &str,
    should_include: bool,
    should_decrypt: bool,
) -> Result<Option<String>> {
    if !should_include {
        return Ok(None);
    }
    if should_decrypt {
        try_decrypt_cipher_subfield(keys, encrypted, cipher_id, field_name)
    } else {
        Ok(encrypted.map(|_| String::new()))
    }
}

fn decrypt_cipher_with_profile(
    cipher: &Cipher,
    keys: &CryptoKeys,
    profile: CipherDecryptionProfile,
) -> Result<CipherOutput> {
    let name = cipher.get_name().context("Cipher has no name")?;
    let decrypted_name = keys.decrypt_to_string(name)?;

    let decrypted_username = decrypt_optional_cipher_value(
        keys,
        cipher.get_username(),
        profile.username,
        profile.decrypt_present_standard_values,
    )?;
    let decrypted_password = decrypt_optional_cipher_value(
        keys,
        cipher.get_password(),
        profile.password,
        profile.decrypt_present_standard_values,
    )?;
    let decrypted_uri = decrypt_optional_cipher_value(
        keys,
        cipher.get_uri(),
        profile.uri,
        profile.decrypt_present_standard_values,
    )?;
    let decrypted_notes = decrypt_optional_cipher_value(
        keys,
        cipher.get_notes(),
        profile.notes,
        profile.decrypt_present_standard_values,
    )?;

    let decrypted_fields = if profile.field_names {
        cipher
            .get_fields()
            .map(|fields| {
                fields
                    .iter()
                    .enumerate()
                    .filter_map(|(index, field)| {
                        let encrypted_name = field.name.as_ref()?;
                        Some((index, field, encrypted_name))
                    })
                    .map(|(index, field, encrypted_name)| {
                        let name = keys.decrypt_to_string(encrypted_name).with_context(|| {
                        format!(
                            "failed to decrypt custom field name at index {index} for cipher {}",
                            cipher.id
                        )
                    })?;
                        let value = field
                            .value
                            .as_ref()
                            .map(|encrypted_value| {
                                if !profile.field_values {
                                    return Ok(String::new());
                                }
                                keys.decrypt_to_string(encrypted_value).with_context(|| {
                                format!(
                                    "failed to decrypt custom field '{name}' value for cipher {}",
                                    cipher.id
                                )
                            })
                            })
                            .transpose()?
                            .unwrap_or_default();
                        Ok(FieldOutput {
                            name,
                            value,
                            hidden: field.r#type == 1,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
    } else {
        None
    };

    // Decrypt SSH key fields if present
    let ssh_public_key = decrypt_optional_cipher_subfield(
        keys,
        cipher
            .ssh_key
            .as_ref()
            .and_then(|s| s.public_key.as_deref()),
        &cipher.id,
        "SSH public key",
        profile.ssh_public_key,
        profile.decrypt_present_standard_values,
    )?;
    let ssh_private_key = decrypt_optional_cipher_subfield(
        keys,
        cipher
            .ssh_key
            .as_ref()
            .and_then(|s| s.private_key.as_deref()),
        &cipher.id,
        "SSH private key",
        profile.ssh_private_key,
        profile.decrypt_present_standard_values,
    )?;
    let ssh_fingerprint = decrypt_optional_cipher_subfield(
        keys,
        cipher
            .ssh_key
            .as_ref()
            .and_then(|s| s.fingerprint.as_deref()),
        &cipher.id,
        "SSH fingerprint",
        profile.ssh_fingerprint,
        profile.decrypt_present_standard_values,
    )?;

    Ok(CipherOutput {
        id: cipher.id.clone(),
        cipher_type: cipher
            .cipher_type()
            .map_or_else(|| "unknown".into(), |t| t.to_string()),
        name: decrypted_name,
        username: decrypted_username,
        password: decrypted_password, // secrets-ignore: derived test data
        uri: decrypted_uri,
        notes: decrypted_notes,
        fields: decrypted_fields,
        ssh_public_key,
        ssh_private_key,
        ssh_fingerprint,
    })
}

fn resolve_org_id(profile: &crate::models::Profile, org_filter: &str) -> Result<String> {
    let matched = profile.organizations.iter().find(|o| {
        o.id == org_filter
            || o.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(org_filter))
    });
    Ok(matched
        .with_context(|| format!("Organization '{org_filter}' not found"))?
        .id
        .clone())
}

fn resolve_collection_id(
    collections: &[crate::models::Collection],
    collection_filter: &str,
    org_id_filter: Option<&str>,
    config: &Config,
) -> Result<String> {
    // Try exact ID match first
    if let Some(c) = collections.iter().find(|c| c.id == collection_filter) {
        return Ok(c.id.clone());
    }

    // Try decrypted name match — collection names are encrypted with the org key
    for col in collections {
        if let Some(oid) = org_id_filter
            && col.organization_id != oid
        {
            continue;
        }
        let keys = match config.get_keys_for_cipher(Some(&col.organization_id)) {
            Some(k) => k,
            None => continue,
        };
        if let Ok(name) = keys.decrypt_to_string(&col.name)
            && name.eq_ignore_ascii_case(collection_filter)
        {
            return Ok(col.id.clone());
        }
    }

    anyhow::bail!("Collection '{collection_filter}' not found")
}

fn output_matches_search(output: &CipherOutput, search_lower: &str) -> bool {
    output.name.to_lowercase().contains(search_lower)
        || output
            .username
            .as_ref()
            .is_some_and(|u| u.to_lowercase().contains(search_lower))
        || output
            .uri
            .as_ref()
            .is_some_and(|u| u.to_lowercase().contains(search_lower))
        || output
            .ssh_public_key
            .as_ref()
            .is_some_and(|k| k.to_lowercase().contains(search_lower))
        || output
            .ssh_fingerprint
            .as_ref()
            .is_some_and(|f| f.to_lowercase().contains(search_lower))
}

pub async fn list(
    type_filter: Option<String>,
    search: Option<String>,
    org_filter: Option<String>,
    collection_filter: Option<String>,
    json_output: bool,
    opts: &CommandOptions,
) -> Result<()> {
    let ctx = load_sync_context(opts.allow_insecure_http).await?;
    let (org_id_filter, collection_id_filter) = resolve_org_and_collection_filters(
        &ctx.sync_response,
        &ctx.config,
        org_filter.as_deref(),
        collection_filter.as_deref(),
    )?;
    let cipher_type_filter = type_filter
        .as_deref()
        .map(CipherType::from_str)
        .transpose()
        .map_err(|_err| {
            anyhow::anyhow!(
                "Invalid type filter: {}. Use: login, note, card, identity, ssh",
                type_filter.as_deref().unwrap_or_default()
            )
        })?;

    let filtered_ciphers;
    let ciphers_source = if org_id_filter.is_some()
        || collection_id_filter.is_some()
        || cipher_type_filter.is_some()
    {
        filtered_ciphers = ctx
            .api
            .ciphers_filtered(
                &ctx.access_token,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                cipher_type_filter.map(|value| value as u8),
            )
            .await?
            .data;
        filtered_ciphers.as_slice()
    } else {
        ctx.sync_response.ciphers.as_slice()
    };

    let ciphers: Vec<&Cipher> = ciphers_source
        .iter()
        .filter(|c| {
            cipher_matches_filters(
                c,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            ) && cipher_type_filter.is_none_or(|cipher_type| c.cipher_type() == Some(cipher_type))
        })
        .collect();

    // Decrypt and filter
    let search_lower = search.as_ref().map(|s| s.to_lowercase());
    let mut outputs: Vec<CipherOutput> = Vec::new();
    for cipher in ciphers {
        let keys = match get_cipher_keys(&ctx.config, cipher) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Warning: No keys for cipher {}: {}", cipher.id, e);
                continue;
            }
        };

        let profile = if json_output || search_lower.is_some() {
            CipherDecryptionProfile::full()
        } else {
            CipherDecryptionProfile::list_env_names()
        };
        match decrypt_cipher_with_profile(cipher, keys, profile) {
            Ok(output) => {
                if let Some(ref term) = search_lower
                    && !output_matches_search(&output, term)
                {
                    continue;
                }
                outputs.push(output);
            }
            Err(e) => {
                eprintln!("Warning: Failed to decrypt cipher {}: {}", cipher.id, e);
            }
        }
    }

    if outputs.is_empty() {
        println!("No items found.");
        return Ok(());
    }

    if json_output {
        ensure_plaintext_json_allowed(opts)?;
    }

    for line in format_list_output(&outputs, json_output)? {
        println!("{line}");
    }

    Ok(())
}

fn format_list_output(outputs: &[CipherOutput], json_output: bool) -> Result<Vec<String>> {
    if json_output {
        return Ok(vec![serde_json::to_string_pretty(outputs)?]);
    }

    let mut lines: Vec<String> = Vec::new();
    for (idx, output) in outputs.iter().enumerate() {
        let mut had_var = false;

        for (name, _) in cipher_to_env_vars(output) {
            lines.push(name);
            had_var = true;
        }

        if had_var && idx + 1 < outputs.len() {
            lines.push(String::new());
        }
    }

    Ok(lines)
}

pub async fn get(
    item: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
    opts: &CommandOptions,
) -> Result<()> {
    if org_filter.is_none() && collection_filter.is_none() {
        let api_ctx = load_api_context(opts.allow_insecure_http).await?;
        if let Ok(output) =
            fetch_cipher_output_by_id(&api_ctx, item, CipherDecryptionProfile::full()).await
        {
            if format == "json" {
                ensure_plaintext_json_allowed(opts)?;
            }
            return print_cipher_output(&output, format);
        }
    }

    let ctx = load_sync_context(opts.allow_insecure_http).await?;
    let (org_id_filter, collection_id_filter) = resolve_org_and_collection_filters(
        &ctx.sync_response,
        &ctx.config,
        org_filter.as_deref(),
        collection_filter.as_deref(),
    )?;

    let matches = |c: &Cipher| -> bool {
        cipher_matches_filters(
            c,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
            None,
        )
    };

    let filtered_ciphers;
    let ciphers = if org_id_filter.is_some() || collection_id_filter.is_some() {
        filtered_ciphers = ctx
            .api
            .ciphers_filtered(
                &ctx.access_token,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            )
            .await?
            .data;
        filtered_ciphers.as_slice()
    } else {
        ctx.sync_response.ciphers.as_slice()
    };

    let output = find_cipher_output_by_name_or_id(
        ciphers,
        &ctx.config,
        item,
        matches,
        CipherDecryptionProfile::full(),
    )?;

    if format == "json" {
        ensure_plaintext_json_allowed(opts)?;
    }
    print_cipher_output(&output, format)
}

pub async fn get_by_uri(
    uri: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
    opts: &CommandOptions,
) -> Result<()> {
    let ctx = load_sync_context(opts.allow_insecure_http).await?;
    let (org_id_filter, collection_id_filter) = resolve_org_and_collection_filters(
        &ctx.sync_response,
        &ctx.config,
        org_filter.as_deref(),
        collection_filter.as_deref(),
    )?;

    let uri_lower = uri.to_lowercase();
    let output = find_cipher_output(
        &ctx.sync_response.ciphers,
        &ctx.config,
        |o| {
            o.uri
                .as_ref()
                .is_some_and(|u| u.to_lowercase().contains(&uri_lower))
        },
        |c| {
            cipher_matches_filters(
                c,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            )
        },
    )
    .context(format!("No item found with URI containing '{uri}'"))?;

    if format == "json" {
        ensure_plaintext_json_allowed(opts)?;
    }
    print_cipher_output(&output, format)
}

fn parse_placeholder(placeholder: &str) -> Result<(String, String)> {
    let mut parts = placeholder.rsplitn(2, '.');
    let component = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if name.is_empty() || component.is_empty() {
        anyhow::bail!("Expected format name.component");
    }
    Ok((name.to_string(), component.to_string()))
}

fn resolve_component(output: &CipherOutput, component: &str) -> Result<String> {
    match component.to_lowercase().as_str() {
        "username" => output.username.clone().context("Item has no username"),
        "password" => output.password.clone().context("Item has no password"),
        "uri" => output.uri.clone().context("Item has no uri"),
        "notes" | "note" => output.notes.clone().context("Item has no notes"),
        "ssh_public_key" | "public_key" | "publickey" => output
            .ssh_public_key
            .clone()
            .context("Item has no SSH public key"),
        "ssh_private_key" | "private_key" | "privatekey" => output
            .ssh_private_key
            .clone()
            .context("Item has no SSH private key"),
        "ssh_fingerprint" | "fingerprint" => output
            .ssh_fingerprint
            .clone()
            .context("Item has no SSH fingerprint"),
        _ => {
            if let Some(fields) = &output.fields
                && let Some(field) = fields
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(component))
            {
                return Ok(field.value.clone());
            }
            anyhow::bail!("Item has no component '{component}'");
        }
    }
}

fn track_missing_placeholder(
    placeholder: &str,
    error: &str,
    full: &str,
    skip_missing: bool,
    missing: &mut Vec<String>,
    unmatched: &mut Vec<String>,
) -> String {
    unmatched.push(full.to_string());
    if !skip_missing {
        missing.push(format!("{placeholder}: {error}"));
    }
    full.to_string()
}

fn build_interpolation_indexes(
    ciphers: &[Cipher],
    config: &Config,
) -> (HashMap<String, Vec<String>>, HashMap<String, String>) {
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    let mut by_id: HashMap<String, String> = HashMap::new();

    for cipher in ciphers {
        let keys = match get_cipher_keys(config, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(output) =
            decrypt_cipher_with_profile(cipher, keys, CipherDecryptionProfile::list_env_names())
        {
            by_id.insert(output.id.clone(), output.id.clone());
            by_name
                .entry(output.name.to_lowercase())
                .or_default()
                .push(output.id);
        }
    }

    (by_name, by_id)
}

fn resolve_interpolation_placeholder(
    raw_name: &str,
    component: &str,
    ciphers: &[Cipher],
    config: &Config,
    by_name: &HashMap<String, Vec<String>>,
    by_id: &HashMap<String, String>,
) -> Result<String> {
    if let Some(cipher_id) = by_id.get(raw_name) {
        let cipher = ciphers
            .iter()
            .find(|cipher| cipher.id == *cipher_id)
            .context("indexed item not found")?;
        let keys = get_cipher_keys(config, cipher)?;
        let output = decrypt_cipher_with_profile(
            cipher,
            keys,
            CipherDecryptionProfile::interpolation(&component.to_lowercase()),
        )?;
        return resolve_component(&output, component);
    }

    let key = raw_name.to_lowercase();
    match by_name.get(&key).map(Vec::as_slice) {
        Some([cipher_id]) => {
            let cipher = ciphers
                .iter()
                .find(|cipher| cipher.id == *cipher_id)
                .context("indexed item not found")?;
            let keys = get_cipher_keys(config, cipher)?;
            let output = decrypt_cipher_with_profile(
                cipher,
                keys,
                CipherDecryptionProfile::interpolation(&component.to_lowercase()),
            )?;
            resolve_component(&output, component)
        }
        Some(matches) => {
            anyhow::bail!("{}", ambiguous_item_name_message(raw_name, matches.len()));
        }
        None => {
            anyhow::bail!("item '{raw_name}' not found");
        }
    }
}

pub async fn interpolate(
    file: &str,
    output_file: Option<&str>,
    skip_missing: bool,
    opts: &CommandOptions,
) -> Result<()> {
    let api_ctx = load_api_context(opts.allow_insecure_http).await?;
    let input =
        fs::read_to_string(file).with_context(|| format!("Failed to read file '{file}'"))?;
    static PLACEHOLDER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\(\(([^\s()]+)\)\)").expect("valid regex"));
    let sync_response = api_ctx.api.sync(&api_ctx.access_token).await?;
    let (by_name, by_id) = build_interpolation_indexes(&sync_response.ciphers, &api_ctx.config);
    let mut missing: Vec<String> = Vec::new();
    let mut unmatched_placeholders: Vec<String> = Vec::new();

    let output = PLACEHOLDER_RE.replace_all(&input, |caps: &regex::Captures| {
        let full_placeholder = caps[0].to_string();
        let placeholder = &caps[1];
        match parse_placeholder(placeholder) {
            Ok((raw_name, component)) => {
                match resolve_interpolation_placeholder(
                    &raw_name,
                    &component,
                    &sync_response.ciphers,
                    &api_ctx.config,
                    &by_name,
                    &by_id,
                ) {
                    Ok(value) => value,
                    Err(err) => track_missing_placeholder(
                        placeholder,
                        &err.to_string(),
                        &full_placeholder,
                        skip_missing,
                        &mut missing,
                        &mut unmatched_placeholders,
                    ),
                }
            }
            Err(err) => track_missing_placeholder(
                placeholder,
                &err.to_string(),
                &full_placeholder,
                skip_missing,
                &mut missing,
                &mut unmatched_placeholders,
            ),
        }
    });

    if !skip_missing && !missing.is_empty() {
        anyhow::bail!("Interpolation failed:\n{}", missing.join("\n"));
    }

    if skip_missing
        && let Some(warning) = format_unmatched_placeholder_warning(&unmatched_placeholders)
    {
        eprintln!("{warning}");
    }

    write_interpolated_output(&output, output_file)?;
    Ok(())
}

fn format_unmatched_placeholder_warning(placeholders: &[String]) -> Option<String> {
    let unique: BTreeSet<&str> = placeholders.iter().map(String::as_str).collect();
    if unique.is_empty() {
        return None;
    }

    Some(format!(
        "Unmatched placeholders left unchanged:\n{}",
        unique.into_iter().collect::<Vec<_>>().join("\n")
    ))
}

fn write_interpolated_output(output: &str, output_file: Option<&str>) -> Result<()> {
    if let Some(path) = output_file {
        let path = std::path::Path::new(path);
        // Use write_secure instead of fs::write + set_permissions to avoid the
        // TOCTOU race: fs::write creates the file at umask mode (typically 0o644)
        // before a separate chmod call narrows it, leaving a brief window where
        // the secret-bearing file is world-readable. write_secure uses fchmod on
        // the open file descriptor before writing any data, closing that window.
        crate::config::write_secure(path, output.as_bytes()).with_context(|| {
            format!(
                "Failed to write interpolated output to '{}'",
                path.display()
            )
        })?;
        Ok(())
    } else {
        print!("{output}");
        Ok(())
    }
}

fn cipher_to_env_vars(output: &CipherOutput) -> Vec<(String, String)> {
    let prefix = sanitize_env_name(&output.name);
    let mut vars: Vec<(String, String)> = Vec::new();
    if let Some(v) = &output.uri {
        vars.push((format!("{prefix}_URI"), v.clone()));
    }
    if let Some(v) = &output.username {
        vars.push((format!("{prefix}_USERNAME"), v.clone()));
    }
    if let Some(v) = &output.password {
        vars.push((format!("{prefix}_PASSWORD"), v.clone()));
    }
    if let Some(v) = &output.ssh_public_key {
        vars.push((format!("{prefix}_SSH_PUBLIC_KEY"), v.clone()));
    }
    if let Some(v) = &output.ssh_private_key {
        vars.push((format!("{prefix}_SSH_PRIVATE_KEY"), v.clone()));
    }
    if let Some(v) = &output.ssh_fingerprint {
        vars.push((format!("{prefix}_SSH_FINGERPRINT"), v.clone()));
    }
    if let Some(fields) = &output.fields {
        for field in fields {
            vars.push((
                format!("{}_{}", prefix, sanitize_env_name(&field.name)),
                field.value.clone(),
            ));
        }
    }
    vars
}

fn get_field_string(field: &Option<String>, name: &str) -> Result<String> {
    field
        .as_deref()
        .with_context(|| format!("Item has no {name}"))
        .map(std::string::ToString::to_string)
}

fn format_cipher_output(output: &CipherOutput, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(output)?),
        "env" => {
            let lines = cipher_to_env_vars(output)
                .into_iter()
                .map(|(name, value)| {
                    Ok(format!(
                        "export {}={}\n",
                        name,
                        shell_quote_env_value(&value)?
                    ))
                })
                .collect::<Result<String>>()?;
            Ok(lines)
        }
        "value" | "password" => get_field_string(&output.password, "password"),
        "username" => get_field_string(&output.username, "username"),
        _ => {
            anyhow::bail!("Unknown format: {format}. Use: json, env, value, username");
        }
    }
}

fn print_cipher_output(output: &CipherOutput, format: &str) -> Result<()> {
    let text = format_cipher_output(output, format)?;
    match format {
        "json" => println!("{text}"),
        _ => print!("{text}"),
    }
    Ok(())
}

fn sanitize_env_name(name: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_separator = true;

    for byte in name.bytes() {
        match byte {
            b'a'..=b'z' => {
                sanitized.push(char::from(byte.to_ascii_uppercase()));
                last_was_separator = false;
            }
            b'A'..=b'Z' | b'0'..=b'9' => {
                sanitized.push(char::from(byte));
                last_was_separator = false;
            }
            _ if !last_was_separator => {
                sanitized.push('_');
                last_was_separator = true;
            }
            _ => {}
        }
    }

    while sanitized.ends_with('_') {
        sanitized.pop();
    }

    if sanitized.is_empty() {
        sanitized.push_str("ITEM");
    } else if sanitized.starts_with(|c: char| c.is_ascii_digit()) {
        sanitized.insert_str(0, "ITEM_");
    }

    sanitized
}

fn shell_quote_env_value(value: &str) -> Result<String> {
    if value.contains('\0') {
        anyhow::bail!("env output cannot represent values containing NUL bytes");
    }

    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_secrets(
    requested_items: &[String],
    search_by_uri: bool,
    org_filter: Option<&str>,
    folder_filter: Option<&str>,
    collection_filter: Option<&str>,
    info_only: bool,
    command: &[String],
    opts: &CommandOptions,
) -> Result<CommandOutcome> {
    if !search_by_uri
        && requested_items.is_empty()
        && org_filter.is_none()
        && folder_filter.is_none()
        && collection_filter.is_none()
    {
        anyhow::bail!(
            "At least one of --name, --org, --folder, or --collection must be specified."
        );
    }
    if !search_by_uri
        && !requested_items.is_empty()
        && org_filter.is_none()
        && folder_filter.is_none()
        && collection_filter.is_none()
    {
        let api_ctx = load_api_context(opts.allow_insecure_http).await?;
        let mut outputs = Vec::with_capacity(requested_items.len());
        let mut all_items_found_by_id = true;
        for item in requested_items {
            match fetch_cipher_output_by_id(&api_ctx, item, CipherDecryptionProfile::run_env())
                .await
            {
                Ok(output) => outputs.push(output),
                Err(_) => {
                    all_items_found_by_id = false;
                    break;
                }
            }
        }
        if all_items_found_by_id {
            return run_with_decrypted_outputs(outputs, info_only, command);
        }
    }

    let ctx = load_sync_context(opts.allow_insecure_http).await?;

    let org_id_filter = org_filter
        .map(|org| resolve_org_id(&ctx.sync_response.profile, org))
        .transpose()?;

    let folder_id_filter: Option<String> = if let Some(folder) = folder_filter {
        if let Some(f) = ctx.sync_response.folders.iter().find(|f| f.id == folder) {
            Some(f.id.clone())
        } else {
            let user_keys = ctx.config.crypto_keys.as_ref().context("Vault locked")?;
            let matched = ctx.sync_response.folders.iter().find(|f| {
                user_keys
                    .decrypt_to_string(&f.name)
                    .ok()
                    .is_some_and(|n| n.eq_ignore_ascii_case(folder))
            });
            Some(
                matched
                    .with_context(|| format!("Folder '{folder}' not found"))?
                    .id
                    .clone(),
            )
        }
    } else {
        None
    };

    let collection_id_filter = collection_filter
        .map(|col| {
            resolve_collection_id(
                &ctx.sync_response.collections,
                col,
                org_id_filter.as_deref(),
                &ctx.config,
            )
        })
        .transpose()?;

    let matches_filters = |cipher: &Cipher| -> bool {
        cipher_matches_filters(
            cipher,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
            folder_id_filter.as_deref(),
        )
    };

    let find_by_name_or_id = |name_or_id: &str| -> Result<CipherOutput> {
        find_cipher_output_by_name_or_id(
            &ctx.sync_response.ciphers,
            &ctx.config,
            name_or_id,
            matches_filters,
            CipherDecryptionProfile::run_env(),
        )
    };

    let outputs: Vec<CipherOutput> = if search_by_uri {
        let uri = requested_items
            .first()
            .context("URI search requires a URI argument")?;
        let uri_lower = uri.to_lowercase();
        vec![
            find_cipher_output(
                &ctx.sync_response.ciphers,
                &ctx.config,
                |o| {
                    o.uri
                        .as_ref()
                        .is_some_and(|u| u.to_lowercase().contains(&uri_lower))
                },
                matches_filters,
            )
            .context(format!("No item found with URI containing '{uri}'"))?,
        ]
    } else if !requested_items.is_empty() {
        requested_items
            .iter()
            .map(|name| find_by_name_or_id(name))
            .collect::<Result<Vec<_>>>()?
    } else if folder_id_filter.is_none() {
        let outputs = fetch_filtered_cipher_outputs(
            &ctx.api,
            &ctx.access_token,
            &ctx.config,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
            None,
            None,
            CipherDecryptionProfile::run_env(),
        )
        .await?;
        if outputs.is_empty() {
            anyhow::bail!("No item found matching the specified filters");
        }
        outputs
    } else {
        let mut outputs = Vec::new();
        let mut failures = Vec::new();
        for cipher in ctx
            .sync_response
            .ciphers
            .iter()
            .filter(|cipher| matches_filters(cipher))
        {
            let output = get_cipher_keys(&ctx.config, cipher)
                .and_then(|keys| {
                    decrypt_cipher_with_profile(cipher, keys, CipherDecryptionProfile::run_env())
                })
                .with_context(|| {
                    format!(
                        "selected filtered item '{}' could not be decrypted",
                        cipher.id
                    )
                });
            match output {
                Ok(output) => outputs.push(output),
                Err(err) => failures.push(format!("{}: {err:#}", cipher.id)),
            }
        }

        if !failures.is_empty() {
            anyhow::bail!(
                "filtered run could not decrypt {} selected item(s): {}",
                failures.len(),
                failures.join("; ")
            );
        }

        if outputs.is_empty() {
            anyhow::bail!("No item found matching the specified filters");
        }

        outputs
    };

    run_with_decrypted_outputs(outputs, info_only, command)
}

fn run_with_decrypted_outputs(
    outputs: Vec<CipherOutput>,
    info_only: bool,
    command: &[String],
) -> Result<CommandOutcome> {
    // Build environment variables from the ciphers
    let mut env_vars = Vec::new();
    for output in outputs {
        env_vars.extend(cipher_to_env_vars(&output));
    }

    // If --info flag, just print variable names
    if info_only {
        println!("Environment variables that would be injected:");
        for (name, _) in &env_vars {
            println!("  {name}");
        }
        return Ok(CommandOutcome::Success);
    }

    // Require a command if not info_only
    if command.is_empty() {
        anyhow::bail!("No command specified. Use -- followed by the command to run.");
    }

    // Spawn the command, inheriting the parent environment but stripping any
    // Vaultwarden credential variables so they are not visible to the child.
    // This is safer than env_clear() which breaks on Windows/macOS where child
    // processes rely on platform-specific variables (SYSTEMROOT, PATHEXT, etc.).
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    // Strip *all* VAULTWARDEN_* and BITWARDEN_* variables from the child
    // environment to prevent credential leakage, regardless of the specific
    // variable name.  Other inherited env vars (PATH, HOME, LANG, …) are kept
    // so the child process works correctly on all platforms.
    let vars_to_remove: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("VAULTWARDEN_") || k.starts_with("BITWARDEN_"))
        .collect();
    for name in vars_to_remove {
        cmd.env_remove(&name);
    }
    for (name, value) in &env_vars {
        cmd.env(name, value);
    }

    // Run the command and wait for it to complete
    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute command: {}", command[0]))?;

    Ok(if status.success() {
        CommandOutcome::Success
    } else {
        CommandOutcome::ChildExit(status)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    mod time_tests {
        use super::*;

        #[test]
        fn system_time_to_unix_seconds_rejects_pre_epoch_time() {
            let err = system_time_to_unix_seconds(UNIX_EPOCH - Duration::from_secs(1)).unwrap_err();
            assert_eq!(err.to_string(), "System clock is before the Unix epoch");
        }

        #[test]
        fn system_time_to_unix_seconds_returns_epoch_seconds() {
            let seconds =
                system_time_to_unix_seconds(UNIX_EPOCH + Duration::from_secs(1_234)).unwrap();
            assert_eq!(seconds, 1_234);
        }
    }

    // Tests for sanitize_env_name
    mod sanitize_env_name_tests {
        use super::*;

        #[test]
        fn test_simple_name() {
            assert_eq!(sanitize_env_name("myapp"), "MYAPP");
        }

        #[test]
        fn test_lowercase_to_uppercase() {
            assert_eq!(sanitize_env_name("my_app"), "MY_APP");
        }

        #[test]
        fn test_spaces_to_underscores() {
            assert_eq!(sanitize_env_name("My App Name"), "MY_APP_NAME");
        }

        #[test]
        fn test_special_characters_to_underscores() {
            assert_eq!(sanitize_env_name("my-app.config"), "MY_APP_CONFIG");
            assert_eq!(sanitize_env_name("app@domain.com"), "APP_DOMAIN_COM");
        }

        #[test]
        fn test_numbers_preserved() {
            assert_eq!(sanitize_env_name("app123"), "APP123");
            assert_eq!(sanitize_env_name("123app"), "ITEM_123APP");
        }

        #[test]
        fn test_mixed_input() {
            assert_eq!(sanitize_env_name("My App-v2.0!"), "MY_APP_V2_0");
        }

        #[test]
        fn test_already_valid_env_name() {
            assert_eq!(sanitize_env_name("MY_APP_NAME"), "MY_APP_NAME");
        }

        #[test]
        fn test_empty_string() {
            assert_eq!(sanitize_env_name(""), "ITEM");
        }

        #[test]
        fn test_unicode_characters() {
            assert_eq!(sanitize_env_name("café"), "CAF");
            assert_eq!(sanitize_env_name("日本語"), "ITEM");
        }

        #[test]
        fn test_consecutive_special_chars() {
            assert_eq!(sanitize_env_name("my--app"), "MY_APP");
            assert_eq!(sanitize_env_name("app...name"), "APP_NAME");
        }

        #[test]
        fn test_edge_case_names_are_portable_identifiers() {
            let names = [
                sanitize_env_name("123 app"),
                sanitize_env_name("日本語"),
                sanitize_env_name("!!!"),
                sanitize_env_name(" café 9 "),
            ];

            for name in names {
                assert!(name.starts_with(|c: char| c.is_ascii_uppercase() || c == '_'));
                assert!(
                    name.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                );
            }
        }
    }

    mod shell_quote_env_value_tests {
        use super::*;

        #[test]
        fn test_no_escaping_needed() {
            assert_eq!(shell_quote_env_value("simple").unwrap(), "'simple'");
            assert_eq!(
                shell_quote_env_value("hello world").unwrap(),
                "'hello world'"
            );
        }

        #[test]
        fn test_quotes_shell_sensitive_bytes_without_expansion() {
            assert_eq!(
                shell_quote_env_value("path\\to\\file \"$HOME\" `pwd`").unwrap(),
                "'path\\to\\file \"$HOME\" `pwd`'"
            );
        }

        #[test]
        fn test_escapes_single_quotes() {
            assert_eq!(
                shell_quote_env_value("can't stop").unwrap(),
                "'can'\\''t stop'"
            );
        }

        #[test]
        fn test_preserves_multiline_and_carriage_return_values() {
            assert_eq!(
                shell_quote_env_value("line one\nline two\rline three").unwrap(),
                "'line one\nline two\rline three'"
            );
        }

        #[test]
        fn test_empty_string() {
            assert_eq!(shell_quote_env_value("").unwrap(), "''");
        }

        #[test]
        fn test_rejects_nul() {
            let err = shell_quote_env_value("before\0after").unwrap_err();
            assert!(
                err.to_string()
                    .contains("env output cannot represent values containing NUL bytes")
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_export_assignment_round_trips_through_shell() {
            let value = "quote ' dollar $HOME backslash \\ newline\ncarriage\r backtick `pwd`";
            let assignment = format!("export SECRET={}", shell_quote_env_value(value).unwrap());
            let output = Command::new("sh")
                .arg("-c")
                .arg(format!("{assignment}; printf %s \"$SECRET\""))
                .output()
                .unwrap();

            assert!(output.status.success());
            assert_eq!(output.stdout, value.as_bytes());
        }
    }

    mod interpolate_helpers_tests {
        use super::*;

        #[test]
        fn test_parse_placeholder_valid() {
            let (name, component) = parse_placeholder("s3.username").unwrap();
            assert_eq!(name, "s3");
            assert_eq!(component, "username");
        }

        #[test]
        fn test_parse_placeholder_uses_last_dot() {
            let (name, component) = parse_placeholder("path.to.s3.token").unwrap();
            assert_eq!(name, "path.to.s3");
            assert_eq!(component, "token");
        }

        #[test]
        fn test_parse_placeholder_invalid() {
            assert!(parse_placeholder("s3").is_err());
            assert!(parse_placeholder("s3.").is_err());
            assert!(parse_placeholder(".username").is_err());
        }

        #[test]
        fn test_resolve_component() {
            let output = CipherOutput {
                id: "1".to_string(),
                cipher_type: "login".to_string(),
                name: "S3".to_string(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                uri: Some("https://example.com".to_string()),
                notes: None,
                fields: Some(vec![FieldOutput {
                    name: "token".to_string(),
                    value: "tok-123".to_string(),
                    hidden: true,
                }]),
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };

            assert_eq!(resolve_component(&output, "username").unwrap(), "user");
            assert_eq!(resolve_component(&output, "password").unwrap(), "pass");
            assert_eq!(
                resolve_component(&output, "uri").unwrap(),
                "https://example.com"
            );
            assert_eq!(resolve_component(&output, "token").unwrap(), "tok-123");
            assert_eq!(resolve_component(&output, "TOKEN").unwrap(), "tok-123");
        }
    }

    mod filter_resolution_tests {
        use super::*;
        use crate::models::{Collection, Organization, Profile};
        use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use cbc::Encryptor;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        type Aes256CbcEnc = Encryptor<aes::Aes256>;

        fn make_profile(orgs: Vec<Organization>) -> Profile {
            Profile {
                id: "user-1".to_string(),
                email: "user@example.com".to_string(),
                name: Some("Test User".to_string()),
                key: None,
                private_key: None,
                organizations: orgs,
            }
        }

        fn encrypt_for_test(plaintext: &str, keys: &CryptoKeys) -> String {
            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = plaintext.as_bytes().to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(&keys.enc_key, &iv)
                .unwrap()
                .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
                .unwrap()
                .to_vec();

            let mut hmac = Hmac::<Sha256>::new_from_slice(&keys.mac_key).unwrap();
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

        #[test]
        fn test_resolve_org_id_matches_exact_id() {
            let profile = make_profile(vec![Organization {
                id: "org-123".to_string(),
                name: Some("Engineering".to_string()),
                key: None,
            }]);

            let org_id = resolve_org_id(&profile, "org-123").unwrap();
            assert_eq!(org_id, "org-123");
        }

        #[test]
        fn test_resolve_org_id_matches_name_case_insensitively() {
            let profile = make_profile(vec![Organization {
                id: "org-123".to_string(),
                name: Some("Engineering".to_string()),
                key: None,
            }]);

            let org_id = resolve_org_id(&profile, "engineering").unwrap();
            assert_eq!(org_id, "org-123");
        }

        #[test]
        fn test_resolve_org_id_errors_when_missing() {
            let profile = make_profile(vec![Organization {
                id: "org-123".to_string(),
                name: Some("Engineering".to_string()),
                key: None,
            }]);

            let err = resolve_org_id(&profile, "sales").unwrap_err();
            assert!(err.to_string().contains("Organization 'sales' not found"));
        }

        #[test]
        fn test_cipher_matches_filters_allows_no_filters() {
            let cipher = Cipher {
                id: "cipher-1".to_string(),
                r#type: 1,
                organization_id: Some("org-1".to_string()),
                name: None,
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                collection_ids: vec!["col-1".to_string()],
                fields: None,
                data: None,
            };

            assert!(cipher_matches_filters(&cipher, None, None, None));
        }

        #[test]
        fn test_cipher_matches_filters_checks_org_and_collection() {
            let cipher = Cipher {
                id: "cipher-1".to_string(),
                r#type: 1,
                organization_id: Some("org-1".to_string()),
                name: None,
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                collection_ids: vec!["col-1".to_string(), "col-2".to_string()],
                fields: None,
                data: None,
            };

            assert!(cipher_matches_filters(
                &cipher,
                Some("org-1"),
                Some("col-2"),
                None
            ));
            assert!(!cipher_matches_filters(
                &cipher,
                Some("org-2"),
                Some("col-2"),
                None
            ));
            assert!(!cipher_matches_filters(
                &cipher,
                Some("org-1"),
                Some("col-9"),
                None
            ));
        }

        #[test]
        fn test_cipher_matches_filters_rejects_nonmatching_folder() {
            let cipher = Cipher {
                id: "cipher-1".to_string(),
                r#type: 1,
                organization_id: None,
                name: None,
                notes: None,
                folder_id: Some("folder-1".to_string()),
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                collection_ids: Vec::new(),
                fields: None,
                data: None,
            };

            assert!(cipher_matches_filters(
                &cipher,
                None,
                None,
                Some("folder-1")
            ));
            assert!(!cipher_matches_filters(
                &cipher,
                None,
                None,
                Some("folder-2")
            ));
        }

        #[test]
        fn test_resolve_collection_id_matches_exact_id() {
            let collection = Collection {
                id: "col-1".to_string(),
                name: "ignored".to_string(),
                organization_id: "org-1".to_string(),
            };

            let config = Config::default();
            let collection_id =
                resolve_collection_id(&[collection], "col-1", None, &config).unwrap();
            assert_eq!(collection_id, "col-1");
        }

        #[test]
        fn test_resolve_collection_id_matches_decrypted_name_with_org_scope() {
            let org_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };
            let mut config = Config::default();
            config
                .org_crypto_keys
                .insert("org-1".to_string(), org_keys.clone());

            let collections = vec![
                Collection {
                    id: "col-ignored".to_string(),
                    name: encrypt_for_test("Shared", &org_keys),
                    organization_id: "org-2".to_string(),
                },
                Collection {
                    id: "col-1".to_string(),
                    name: encrypt_for_test("Shared", &org_keys),
                    organization_id: "org-1".to_string(),
                },
            ];

            let collection_id =
                resolve_collection_id(&collections, "shared", Some("org-1"), &config).unwrap();
            assert_eq!(collection_id, "col-1");
        }

        #[test]
        fn test_resolve_collection_id_errors_without_matching_decrypted_name() {
            let config = Config::default();
            let collections = vec![Collection {
                id: "col-1".to_string(),
                name: "2.unreadable".to_string(),
                organization_id: "org-1".to_string(),
            }];

            let err = resolve_collection_id(&collections, "missing", None, &config).unwrap_err();
            assert!(err.to_string().contains("Collection 'missing' not found"));
        }
    }

    // Tests for decrypt_cipher helper
    mod decrypt_cipher_tests {
        use super::*;
        use crate::models::{Cipher, FieldData, LoginData, SshKeyData, UriData};

        fn create_test_cipher(id: &str, cipher_type: u8) -> Cipher {
            Cipher {
                id: id.to_string(),
                r#type: cipher_type,
                organization_id: None,
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                fields: None,
                data: None,
            }
        }

        fn test_crypto_keys() -> CryptoKeys {
            CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            }
        }

        fn encrypt_for_decrypt_cipher_test(value: &str, crypto_keys: &CryptoKeys) -> String {
            crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                value.as_bytes(),
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            )
        }

        fn create_named_test_cipher(id: &str, cipher_type: u8, keys: &CryptoKeys) -> Cipher {
            let mut cipher = create_test_cipher(id, cipher_type);
            cipher.name = Some(encrypt_for_decrypt_cipher_test("Test Item", keys));
            cipher
        }

        #[test]
        fn test_list_env_name_profile_skips_secret_value_decryption() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("test-123", 1, &keys);
            cipher.login = Some(LoginData {
                username: Some("not-encrypted".to_string()),
                password: Some("also-not-encrypted".to_string()),
                totp: None,
                uris: Some(vec![UriData {
                    uri: Some("bad-uri".to_string()),
                    r#match: None,
                }]),
            });

            let output = decrypt_cipher_with_profile(
                &cipher,
                &keys,
                CipherDecryptionProfile::list_env_names(),
            )
            .expect("list env-name profile should not decrypt present secret values");

            assert_eq!(output.name, "Test Item");
            assert_eq!(output.username.as_deref(), Some(""));
            assert_eq!(output.password.as_deref(), Some(""));
            assert_eq!(output.uri.as_deref(), Some(""));
        }

        #[test]
        fn test_run_env_profile_skips_unused_uri_decryption() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("test-123", 1, &keys);
            cipher.login = Some(LoginData {
                username: Some(encrypt_for_decrypt_cipher_test("alice", &keys)),
                password: Some(encrypt_for_decrypt_cipher_test("secret", &keys)),
                totp: None,
                uris: Some(vec![UriData {
                    uri: Some("not-encrypted".to_string()),
                    r#match: None,
                }]),
            });

            let output =
                decrypt_cipher_with_profile(&cipher, &keys, CipherDecryptionProfile::run_env())
                    .expect("run env profile should ignore URI decryption failures");

            assert_eq!(output.username.as_deref(), Some("alice"));
            assert_eq!(output.password.as_deref(), Some("secret"));
            assert_eq!(output.uri, None);
        }

        #[test]
        fn test_interpolation_profile_decrypts_only_requested_component() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("test-123", 1, &keys);
            cipher.login = Some(LoginData {
                username: Some("not-encrypted".to_string()),
                password: Some(encrypt_for_decrypt_cipher_test("secret", &keys)),
                totp: None,
                uris: None,
            });

            let output = decrypt_cipher_with_profile(
                &cipher,
                &keys,
                CipherDecryptionProfile::interpolation("password"),
            )
            .expect("password interpolation should not decrypt username");

            assert_eq!(output.username, None);
            assert_eq!(output.password.as_deref(), Some("secret"));
        }

        #[test]
        fn test_decrypt_cipher_no_name_fails() {
            let cipher = create_test_cipher("test-123", 1);
            let keys = CryptoKeys {
                enc_key: vec![0u8; 32],
                mac_key: vec![0u8; 32],
            };

            let result = decrypt_cipher(&cipher, &keys);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("no name"));
        }

        #[test]
        fn test_cipher_type_to_string() {
            // Test that cipher types are converted correctly
            let mut cipher = create_test_cipher("test", 1);
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "login");

            cipher.r#type = 2;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "note");

            cipher.r#type = 3;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "card");

            cipher.r#type = 4;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "identity");

            cipher.r#type = 5;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "ssh");

            cipher.r#type = 6;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "ssh");
        }

        #[test]
        fn test_decrypt_cipher_errors_on_invalid_custom_field_name() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("cipher-1", 1, &keys);
            cipher.fields = Some(vec![FieldData {
                name: Some("not encrypted".to_string()),
                value: Some(encrypt_for_decrypt_cipher_test("secret", &keys)),
                r#type: 1,
            }]);

            let err = decrypt_cipher(&cipher, &keys).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("failed to decrypt custom field name at index 0"));
            assert!(message.contains("cipher-1"));
        }

        #[test]
        fn test_decrypt_cipher_errors_on_invalid_custom_field_value() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("cipher-1", 1, &keys);
            cipher.fields = Some(vec![FieldData {
                name: Some(encrypt_for_decrypt_cipher_test("api token", &keys)),
                value: Some("not encrypted".to_string()),
                r#type: 1,
            }]);

            let err = decrypt_cipher(&cipher, &keys).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("failed to decrypt custom field 'api token' value"));
            assert!(message.contains("cipher-1"));
        }

        #[test]
        fn test_decrypt_cipher_errors_on_invalid_ssh_public_key() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("cipher-ssh", 5, &keys);
            cipher.ssh_key = Some(SshKeyData {
                public_key: Some("not encrypted".to_string()),
                private_key: Some(encrypt_for_decrypt_cipher_test("private", &keys)),
                fingerprint: Some(encrypt_for_decrypt_cipher_test("fingerprint", &keys)),
            });

            let err = decrypt_cipher(&cipher, &keys).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("failed to decrypt SSH public key"));
            assert!(message.contains("cipher-ssh"));
        }

        #[test]
        fn test_decrypt_cipher_errors_on_invalid_ssh_private_key() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("cipher-ssh", 5, &keys);
            cipher.ssh_key = Some(SshKeyData {
                public_key: Some(encrypt_for_decrypt_cipher_test("public", &keys)),
                private_key: Some("not encrypted".to_string()),
                fingerprint: Some(encrypt_for_decrypt_cipher_test("fingerprint", &keys)),
            });

            let err = decrypt_cipher(&cipher, &keys).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("failed to decrypt SSH private key"));
            assert!(message.contains("cipher-ssh"));
        }

        #[test]
        fn test_decrypt_cipher_errors_on_invalid_ssh_fingerprint() {
            let keys = test_crypto_keys();
            let mut cipher = create_named_test_cipher("cipher-ssh", 5, &keys);
            cipher.ssh_key = Some(SshKeyData {
                public_key: Some(encrypt_for_decrypt_cipher_test("public", &keys)),
                private_key: Some(encrypt_for_decrypt_cipher_test("private", &keys)),
                fingerprint: Some("not encrypted".to_string()),
            });

            let err = decrypt_cipher(&cipher, &keys).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("failed to decrypt SSH fingerprint"));
            assert!(message.contains("cipher-ssh"));
        }
    }

    // Tests for ensure_unlocked helper
    mod ensure_unlocked_tests {
        use super::*;

        #[test]
        fn test_ensure_unlocked_with_keys() {
            let config = Config {
                crypto_keys: Some(CryptoKeys {
                    enc_key: vec![0u8; 32],
                    mac_key: vec![0u8; 32],
                }),
                ..Default::default()
            };

            let result = ensure_unlocked(&config);
            assert!(result.is_ok());
        }

        #[test]
        fn test_ensure_unlocked_without_keys() {
            let config = Config::default();

            let result = ensure_unlocked(&config);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("locked"));
        }
    }

    // Tests for status, lock, and logout commands
    mod command_state_tests {
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

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn mock_entry(user: &str) -> keyring_core::Entry {
            keyring_core::Entry::new("vaultwarden-cli", user)
                .expect("mock keyring entry should be created")
        }

        fn fail_next_keyring_call(entry: &keyring_core::Entry) {
            let mock = entry
                .as_any()
                .downcast_ref::<keyring_core::mock::Cred>()
                .expect("entry should come from mock keyring");
            mock.set_error(keyring_core::Error::Invalid(
                "delete".to_string(),
                "simulated failure".to_string(),
            ));
        }

        #[tokio::test]
        async fn test_status_when_not_logged_in() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let result = status().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_status_when_logged_in_locked() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                client_id: Some("client-123".to_string()),
                email: Some("user@example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                ..Default::default()
            };
            config.save().unwrap();

            let result = status().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_status_when_logged_in_unlocked() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mut config = Config {
                server: Some("https://vault.example.com".to_string()),
                client_id: Some("client-123".to_string()),
                email: Some("user@example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                ..Default::default()
            };
            config.crypto_keys = Some(CryptoKeys {
                enc_key: vec![0u8; 32],
                mac_key: vec![0u8; 32],
            });
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = status().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_status_token_expired() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(0),
                ..Default::default()
            };
            config.save().unwrap();

            let result = status().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_lock_deletes_saved_keys() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mut config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                ..Default::default()
            };
            config.crypto_keys = Some(CryptoKeys {
                enc_key: vec![0u8; 32],
                mac_key: vec![0u8; 32],
            });
            config.save().unwrap();
            config.save_keys().unwrap();

            assert!(Config::keys_path().unwrap().exists());

            let result = lock().await;
            assert!(result.is_ok());
            assert!(!Config::keys_path().unwrap().exists());
            assert!(Config::config_path().unwrap().exists());
        }

        #[tokio::test]
        async fn test_lock_reports_keyring_delete_failure() {
            let _guard = ENV_LOCK.lock().await;
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let entry = mock_entry("client-lock-fail:keys");
            entry.set_password("saved keys").unwrap();
            fail_next_keyring_call(&entry);

            let config = Config {
                client_id: Some("client-lock-fail".to_string()),
                ..Default::default()
            };

            let err =
                lock_loaded_config(&config).expect_err("lock should report keyring delete failure");

            assert!(
                err.to_string()
                    .contains("Failed to delete saved vault keys from system keyring"),
                "unexpected error: {err:#}"
            );
        }

        #[tokio::test]
        async fn test_logout_when_not_logged_in() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let result = logout().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_logout_clears_config_and_keys() {
            let _guard = ENV_LOCK.lock().await;
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mut config = Config {
                server: Some("https://vault.example.com".to_string()),
                client_id: Some("client-123".to_string()),
                email: Some("user@example.com".to_string()),
                access_token: Some("token".to_string()),
                refresh_token: Some("refresh".to_string()),
                token_expiry: Some(1234567890),
                encrypted_key: Some("enc-key".to_string()),
                encrypted_private_key: Some("priv-key".to_string()),
                ..Default::default()
            };
            config
                .org_keys
                .insert("org-1".to_string(), "key".to_string());
            config.crypto_keys = Some(CryptoKeys {
                enc_key: vec![0u8; 32],
                mac_key: vec![0u8; 32],
            });
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = logout_loaded_config(Config::load().unwrap());
            assert!(result.is_ok());

            let loaded = Config::load().unwrap();
            assert!(!loaded.is_logged_in());
            assert!(!loaded.is_unlocked());
            assert!(loaded.access_token.is_none());
            assert!(loaded.refresh_token.is_none());
            assert!(loaded.token_expiry.is_none());
            assert!(loaded.crypto_keys.is_none());
            assert!(loaded.encrypted_key.is_none());
            assert!(loaded.encrypted_private_key.is_none());
            assert!(loaded.org_keys.is_empty());
            assert!(loaded.org_crypto_keys.is_empty());
            assert!(!Config::keys_path().unwrap().exists());
        }

        #[tokio::test]
        async fn test_logout_reports_client_secret_delete_failure() {
            let _guard = ENV_LOCK.lock().await;
            let _keyring_guard = crate::KEYRING_TEST_LOCK.lock().unwrap();
            let _mock_keyring = MockKeyring::install();
            let entry = mock_entry("client-logout-fail");
            entry.set_password("client secret").unwrap();
            fail_next_keyring_call(&entry);

            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                client_id: Some("client-logout-fail".to_string()),
                access_token: Some("token".to_string()),
                ..Default::default()
            };

            let err = logout_loaded_config(config)
                .expect_err("logout should report client secret delete failure");

            assert!(
                err.to_string()
                    .contains("Failed to delete client secret from system keyring"),
                "unexpected error: {err:#}"
            );
        }
    }

    // Tests for login command
    mod login_tests {
        use super::*;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        async fn mount_reachable_server(mock_server: &MockServer) {
            Mock::given(method("GET"))
                .and(path("/alive"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(mock_server)
                .await;
        }

        async fn mount_login_token_response(mock_server: &MockServer, expires_in: i64) {
            let token_response = serde_json::json!({
                "access_token": "access-123",
                "expires_in": expires_in,
                "token_type": "Bearer",
                "refresh_token": "refresh-123",
                "scope": "api",
                "key": "2.encrypted-key",
                "privateKey": "2.encrypted-private-key",
                "kdf": 0,
                "kdfIterations": 600000
            });

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .and(body_string_contains("grant_type=client_credentials"))
                .and(body_string_contains("client_id=test-client"))
                .and(body_string_contains("client_secret=test-secret"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .expect(1)
                .mount(mock_server)
                .await;
        }

        #[tokio::test]
        async fn test_login_success_with_provided_credentials() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            mount_reachable_server(&mock_server).await;
            mount_login_token_response(&mock_server, 3600).await;

            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "name": "Test User",
                    "privateKey": "2.encrypted-private-key",
                    "organizations": [
                        {
                            "id": "org-1",
                            "name": "Engineering",
                            "key": "2.org-key"
                        }
                    ]
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let before_login = unix_now().unwrap();
            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("test-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_ok());

            let config = Config::load().unwrap();
            assert_eq!(config.server, Some(mock_server.uri()));
            assert_eq!(config.client_id, Some("test-client".to_string()));
            assert_eq!(config.access_token, Some("access-123".to_string()));
            assert_eq!(config.refresh_token, Some("refresh-123".to_string()));
            assert_eq!(config.email, Some("user@example.com".to_string()));
            assert_eq!(config.encrypted_key, Some("2.encrypted-key".to_string()));
            assert_eq!(
                config.encrypted_private_key,
                Some("2.encrypted-private-key".to_string())
            );
            assert_eq!(config.kdf_iterations, Some(600000));
            assert_eq!(config.org_keys.get("org-1"), Some(&"2.org-key".to_string()));
            let token_expiry = config.token_expiry.unwrap();
            assert!(token_expiry >= before_login + 3600);
            assert!(token_expiry <= unix_now().unwrap() + 3600);
        }

        #[tokio::test]
        async fn test_login_sync_failure_does_not_persist_logged_in_session() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            mount_reachable_server(&mock_server).await;
            mount_login_token_response(&mock_server, 3600).await;

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(500).set_body_string("sync failed"))
                .expect(1)
                .mount(&mock_server)
                .await;

            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("test-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_err());

            let config = Config::load().unwrap();
            assert!(!config.is_logged_in());
            assert!(config.server.is_none());
            assert!(config.client_id.is_none());
            assert!(config.access_token.is_none());
            assert!(config.refresh_token.is_none());
            assert!(config.token_expiry.is_none());
            assert!(config.email.is_none());
            assert!(config.encrypted_key.is_none());
            assert!(config.encrypted_private_key.is_none());
            assert!(config.org_keys.is_empty());
            assert!(!Config::tokens_path().unwrap().exists());
        }

        async fn assert_login_rejects_invalid_expires_in(expires_in: i64) {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            mount_reachable_server(&mock_server).await;
            mount_login_token_response(&mock_server, expires_in).await;

            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("test-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                "Server returned invalid token lifetime: expires_in must be positive"
            );

            let config = Config::load().unwrap();
            assert!(config.access_token.is_none());
            assert!(config.refresh_token.is_none());
            assert!(config.token_expiry.is_none());
        }

        #[tokio::test]
        async fn test_login_rejects_zero_expires_in() {
            let _guard = ENV_LOCK.lock().await;
            assert_login_rejects_invalid_expires_in(0).await;
        }

        #[tokio::test]
        async fn test_login_rejects_negative_expires_in() {
            let _guard = ENV_LOCK.lock().await;
            assert_login_rejects_invalid_expires_in(-60).await;
        }

        #[tokio::test]
        async fn test_login_fails_when_server_unreachable() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/alive"))
                .respond_with(ResponseTemplate::new(503))
                .expect(1)
                .mount(&mock_server)
                .await;

            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("test-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Server is not reachable")
            );
        }

        #[tokio::test]
        async fn test_login_fails_on_invalid_credentials() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/alive"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&mock_server)
                .await;

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .respond_with(
                    ResponseTemplate::new(401).set_body_string("{\"error\":\"invalid_client\"}"),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("bad-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_login_uses_existing_config_server_and_client_id() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let existing = Config {
                server: Some(mock_server.uri()),
                client_id: Some("existing-client".to_string()),
                ..Default::default()
            };
            existing.save().unwrap();

            Mock::given(method("GET"))
                .and(path("/alive"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&mock_server)
                .await;

            let token_response = serde_json::json!({
                "access_token": "access-123",
                "expires_in": 3600,
                "token_type": "Bearer",
                "key": "2.encrypted-key",
                "kdfIterations": 600000
            });

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .and(body_string_contains("client_id=existing-client"))
                .and(body_string_contains("client_secret=new-secret"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let result = login(
                None,
                None,
                Some("new-secret".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_ok());

            let config = Config::load().unwrap();
            assert_eq!(config.server, Some(mock_server.uri()));
            assert_eq!(config.client_id, Some("existing-client".to_string()));
            assert_eq!(config.access_token, Some("access-123".to_string()));
        }
    }

    // Tests for unlock command
    mod unlock_tests {
        use super::*;
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
        use sha2::Sha256;

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn encrypt_symmetric_key_for_test(
            symmetric_key: &[u8],
            password: &str,
            email: &str,
            iterations: u32,
        ) -> String {
            use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
            use cbc::Encryptor;
            use hmac::{Hmac, KeyInit, Mac};

            type Aes256CbcEnc = Encryptor<aes::Aes256>;

            let master_key = CryptoKeys::derive_master_key(password, email, iterations);
            let stretched = CryptoKeys::stretch_master_key(&master_key).unwrap();

            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = symmetric_key.to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(&stretched.enc_key, &iv)
                .unwrap()
                .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
                .unwrap()
                .to_vec();

            let mut hmac = Hmac::<Sha256>::new_from_slice(&stretched.mac_key).unwrap();
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

        fn encrypt_bytes_for_test(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> String {
            use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
            use cbc::Encryptor;
            use hmac::{Hmac, KeyInit, Mac};

            type Aes256CbcEnc = Encryptor<aes::Aes256>;

            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = plaintext.to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(enc_key, &iv)
                .unwrap()
                .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
                .unwrap()
                .to_vec();

            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
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

        #[tokio::test]
        async fn test_unlock_fails_when_not_logged_in() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let result = unlock(Some("password".to_string()), &Default::default()).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Not logged in"));
        }

        #[tokio::test]
        async fn test_unlock_with_password_argument() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let mut symmetric_key = keys.enc_key.clone();
            symmetric_key.extend_from_slice(&keys.mac_key);

            let encrypted_key = encrypt_symmetric_key_for_test(
                &symmetric_key,
                "master-password",
                "user@example.com",
                100000,
            );

            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                encrypted_key: Some(encrypted_key),
                kdf_iterations: Some(100000),
                ..Default::default()
            };
            config.save().unwrap();

            let result = unlock(Some("master-password".to_string()), &Default::default()).await;
            assert!(result.is_ok());

            let loaded = Config::load().unwrap();
            assert!(loaded.is_unlocked());
            assert!(Config::keys_path().unwrap().exists());
        }

        #[tokio::test]
        async fn test_unlock_fails_with_wrong_password() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let mut symmetric_key = keys.enc_key.clone();
            symmetric_key.extend_from_slice(&keys.mac_key);

            let encrypted_key = encrypt_symmetric_key_for_test(
                &symmetric_key,
                "master-password",
                "user@example.com",
                100000,
            );

            let config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                encrypted_key: Some(encrypted_key),
                kdf_iterations: Some(100000),
                ..Default::default()
            };
            config.save().unwrap();

            let result = unlock(Some("wrong-password".to_string()), &Default::default()).await;
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Failed to decrypt vault key")
            );
        }

        #[tokio::test]
        async fn test_unlock_decrypts_org_keys() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let user_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let mut symmetric_key = user_keys.enc_key.clone();
            symmetric_key.extend_from_slice(&user_keys.mac_key);

            let encrypted_key = encrypt_symmetric_key_for_test(
                &symmetric_key,
                "master-password",
                "user@example.com",
                100000,
            );

            // Generate RSA key pair
            let mut rng = rand::rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);
            let der = private_key.to_pkcs8_der().unwrap().as_bytes().to_vec();

            let encrypted_private_key =
                encrypt_bytes_for_test(&der, &user_keys.enc_key, &user_keys.mac_key);

            // Encrypt org symmetric key with RSA
            let org_symmetric_key: Vec<u8> = (0..64).collect();
            let padding = Oaep::<Sha256>::new();
            let encrypted_org_key = public_key
                .encrypt(&mut rng, padding, &org_symmetric_key)
                .unwrap();
            let encrypted_org_key_str = format!("6.{}", BASE64.encode(&encrypted_org_key));

            let mut config = Config {
                server: Some("https://vault.example.com".to_string()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                encrypted_key: Some(encrypted_key),
                encrypted_private_key: Some(encrypted_private_key),
                kdf_iterations: Some(100000),
                ..Default::default()
            };
            config
                .org_keys
                .insert("org-1".to_string(), encrypted_org_key_str);
            config.save().unwrap();

            let result = unlock(Some("master-password".to_string()), &Default::default()).await;
            assert!(result.is_ok());

            let loaded = Config::load().unwrap();
            assert!(loaded.is_unlocked());
            let org_keys = loaded
                .org_crypto_keys
                .get("org-1")
                .expect("org key present");
            assert_eq!(org_keys.enc_key, org_symmetric_key[0..32]);
            assert_eq!(org_keys.mac_key, org_symmetric_key[32..64]);
        }
    }

    mod query_helpers_tests {
        use super::*;

        #[test]
        fn test_try_decrypt_some() {
            let keys = crate::crypto::tests::test_helpers::encrypt_bytes_for_test;
            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let encrypted = keys(b"secret", &crypto_keys.enc_key, &crypto_keys.mac_key);
            let result = try_decrypt(&crypto_keys, Some(&encrypted)).unwrap();
            assert_eq!(result, Some("secret".to_string()));
        }

        #[test]
        fn test_try_decrypt_none() {
            let crypto_keys = CryptoKeys {
                enc_key: vec![0u8; 32],
                mac_key: vec![0u8; 32],
            };
            let result = try_decrypt(&crypto_keys, None).unwrap();
            assert_eq!(result, None);
        }

        #[test]
        fn test_get_field_string_some() {
            assert_eq!(
                get_field_string(&Some("value".to_string()), "username").unwrap(),
                "value"
            );
        }

        #[test]
        fn test_get_field_string_none() {
            let err = get_field_string(&None, "password").unwrap_err();
            assert!(err.to_string().contains("Item has no password"));
        }

        #[test]
        fn test_output_matches_search_name() {
            let output = CipherOutput {
                id: "1".to_string(),
                cipher_type: "login".to_string(),
                name: "My Secret App".to_string(),
                username: None,
                password: None,
                uri: None,
                notes: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };
            assert!(output_matches_search(&output, "secret"));
        }

        #[test]
        fn test_output_matches_search_username() {
            let output = CipherOutput {
                id: "1".to_string(),
                cipher_type: "login".to_string(),
                name: "App".to_string(),
                username: Some("admin@example.com".to_string()),
                password: None,
                uri: None,
                notes: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };
            assert!(output_matches_search(&output, "admin"));
        }

        #[test]
        fn test_output_matches_search_uri() {
            let output = CipherOutput {
                id: "1".to_string(),
                cipher_type: "login".to_string(),
                name: "App".to_string(),
                username: None,
                password: None,
                uri: Some("https://github.com".to_string()),
                notes: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };
            assert!(output_matches_search(&output, "github"));
        }

        #[test]
        fn test_output_matches_search_no_match() {
            let output = CipherOutput {
                id: "1".to_string(),
                cipher_type: "login".to_string(),
                name: "App".to_string(),
                username: Some("user".to_string()),
                password: None,
                uri: Some("https://example.com".to_string()),
                notes: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };
            assert!(!output_matches_search(&output, "missing"));
        }

        #[test]
        fn test_find_cipher_output_finds_match() {
            use crate::models::Cipher;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let config = Config {
                crypto_keys: Some(crypto_keys.clone()),
                ..Default::default()
            };

            let encrypted_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                b"Target",
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            );

            let ciphers = vec![Cipher {
                id: "cipher-1".to_string(),
                r#type: 1,
                organization_id: None,
                name: Some(encrypted_name),
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                collection_ids: Vec::new(),
                fields: None,
                data: None,
            }];

            let result = find_cipher_output(&ciphers, &config, |o| o.name == "Target", |_c| true);
            assert!(result.is_some());
            assert_eq!(result.unwrap().name, "Target");
        }

        #[test]
        fn test_find_cipher_output_no_match() {
            use crate::models::Cipher;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };
            let config = Config {
                crypto_keys: Some(crypto_keys.clone()),
                ..Default::default()
            };

            let encrypted_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                b"Other",
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            );

            let ciphers = vec![Cipher {
                id: "cipher-1".to_string(),
                r#type: 1,
                organization_id: None,
                name: Some(encrypted_name),
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                collection_ids: Vec::new(),
                fields: None,
                data: None,
            }];

            let result = find_cipher_output(&ciphers, &config, |o| o.name == "Target", |_c| true);
            assert!(result.is_none());
        }
    }

    // Tests for interpolate command
    mod interpolate_tests {
        use super::*;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn encrypt_for_interpolate_test(value: &str, crypto_keys: &CryptoKeys) -> String {
            crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                value.as_bytes(),
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            )
        }

        fn make_sync_response_with_logins(
            logins: &[(&str, &str, &str, &str)],
        ) -> serde_json::Value {
            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let ciphers = logins
                .iter()
                .map(|(id, name, username, password)| {
                    let encrypted_name = encrypt_for_interpolate_test(name, &crypto_keys);
                    let encrypted_user = encrypt_for_interpolate_test(username, &crypto_keys);
                    let encrypted_pass = encrypt_for_interpolate_test(password, &crypto_keys);

                    serde_json::json!({
                        "id": id,
                        "type": 1,
                        "name": encrypted_name,
                        "login": {
                            "username": encrypted_user,
                            "password": encrypted_pass,
                            "uris": null,
                            "totp": null
                        },
                        "collectionIds": [],
                        "organizationId": null
                    })
                })
                .collect::<Vec<_>>();

            serde_json::json!({
                "ciphers": ciphers,
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            })
        }

        fn make_sync_response_with_one_login() -> serde_json::Value {
            make_sync_response_with_logins(&[("cipher-1", "MyLogin", "myuser", "mypass")])
        }

        fn make_collection_response_with_missing_org_key() -> serde_json::Value {
            let crypto_keys = test_crypto_keys();

            serde_json::json!({
                "ciphers": [
                    {
                        "id": "cipher-1",
                        "type": 1,
                        "name": encrypt_for_interpolate_test("GoodLogin", &crypto_keys),
                        "login": {
                            "username": encrypt_for_interpolate_test("good-user", &crypto_keys),
                            "password": encrypt_for_interpolate_test("good-pass", &crypto_keys),
                            "uris": null,
                            "totp": null
                        },
                        "collectionIds": ["DZ1"],
                        "organizationId": null
                    },
                    {
                        "id": "cipher-2",
                        "type": 1,
                        "name": encrypt_for_interpolate_test("MissingOrgKey", &crypto_keys),
                        "login": {
                            "username": encrypt_for_interpolate_test("bad-user", &crypto_keys),
                            "password": encrypt_for_interpolate_test("bad-pass", &crypto_keys),
                            "uris": null,
                            "totp": null
                        },
                        "collectionIds": ["DZ1"],
                        "organizationId": "org-1"
                    }
                ],
                "folders": [],
                "collections": [
                    {
                        "id": "DZ1",
                        "name": "collection-name-not-needed-for-id-match",
                        "organizationId": "org-1"
                    }
                ],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            })
        }

        fn test_crypto_keys() -> CryptoKeys {
            CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            }
        }

        async fn mount_sync_response(mock_server: &MockServer, sync_response: serde_json::Value) {
            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(mock_server)
                .await;
        }

        fn save_unlocked_test_config(mock_server: &MockServer) {
            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(test_crypto_keys()),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();
        }

        #[tokio::test]
        async fn test_run_with_secrets_returns_child_exit_without_terminating_caller() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            mount_sync_response(&mock_server, make_sync_response_with_one_login()).await;
            save_unlocked_test_config(&mock_server);

            let outcome = run_with_secrets(
                &[String::from("MyLogin")],
                false,
                None,
                None,
                None,
                false,
                &[String::from("false")],
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await
            .expect("run_with_secrets should return child status");

            match outcome {
                CommandOutcome::ChildExit(status) => assert_eq!(status.code(), Some(1)),
                CommandOutcome::Success => panic!("expected child failure status"),
            }
        }

        #[tokio::test]
        async fn test_run_with_secrets_errors_on_empty_uri_search_input() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            mount_sync_response(&mock_server, make_sync_response_with_one_login()).await;
            save_unlocked_test_config(&mock_server);

            let err = run_with_secrets(
                &[],
                true,
                None,
                None,
                None,
                false,
                &[String::from("true")],
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("empty URI search should return an error");

            assert!(
                err.to_string()
                    .contains("URI search requires a URI argument")
            );
        }

        #[tokio::test]
        async fn test_run_with_secrets_fails_on_duplicate_item_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            mount_sync_response(
                &mock_server,
                make_sync_response_with_logins(&[
                    ("cipher-1", "MyLogin", "first-user", "first-pass"),
                    ("cipher-2", "mylogin", "second-user", "second-pass"),
                ]),
            )
            .await;
            save_unlocked_test_config(&mock_server);

            let err = run_with_secrets(
                &[String::from("MyLogin")],
                false,
                None,
                None,
                None,
                false,
                &[String::from("true")],
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("duplicate item names should be ambiguous");

            let message = err.to_string();
            assert!(message.contains("item name 'MyLogin' is ambiguous"));
            assert!(message.contains("2 vault items match case-insensitively"));
        }

        #[tokio::test]
        async fn test_run_with_secrets_allows_id_to_disambiguate_duplicate_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let sync_response = make_sync_response_with_logins(&[
                ("cipher-1", "MyLogin", "first-user", "first-pass"),
                ("cipher-2", "mylogin", "second-user", "second-pass"),
            ]);
            Mock::given(method("GET"))
                .and(path("/api/ciphers/cipher-2"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(sync_response["ciphers"][1].clone()),
                )
                .expect(1)
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(0)
                .mount(&mock_server)
                .await;
            save_unlocked_test_config(&mock_server);

            let result = run_with_secrets(
                &[String::from("cipher-2")],
                false,
                None,
                None,
                None,
                false,
                &[String::from("true")],
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(matches!(result, Ok(CommandOutcome::Success)));
        }

        #[tokio::test]
        async fn test_run_with_collection_filter_fails_on_selected_missing_org_key() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let full_response = make_collection_response_with_missing_org_key();
            let mut sync_response = full_response.clone();
            sync_response["ciphers"] = serde_json::json!([]);
            mount_sync_response(&mock_server, sync_response).await;
            let ciphers_response = serde_json::json!({
                "object": "list",
                "data": full_response["ciphers"].clone()
            });
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("collectionId", "DZ1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&ciphers_response))
                .expect(1)
                .mount(&mock_server)
                .await;
            save_unlocked_test_config(&mock_server);

            let err = run_with_secrets(
                &[],
                false,
                None,
                None,
                Some("DZ1"),
                false,
                &[String::from("true")],
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("selected filtered item without keys should fail the run");

            let message = err.to_string();
            assert!(message.contains("filtered run could not decrypt 1 selected item(s)"));
            assert!(message.contains("cipher-2"));
            assert!(message.contains("Organization key not available for org org-1"));
        }

        #[tokio::test]
        async fn test_interpolate_replaces_placeholders() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(
                &input_path,
                "user: ((MyLogin.username))\npass: ((MyLogin.password))\n",
            )
            .unwrap();

            let result = interpolate(
                input_path.to_str().unwrap(),
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_interpolate_writes_to_output_file() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((MyLogin.username))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());

            let output = std::fs::read_to_string(&output_path).unwrap();
            assert_eq!(output, "user: myuser\n");
        }

        #[tokio::test]
        async fn test_interpolate_fails_on_missing_placeholder() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "missing: ((Unknown.item))\n").unwrap();

            let result = interpolate(
                input_path.to_str().unwrap(),
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Interpolation failed")
            );
        }

        #[tokio::test]
        async fn test_interpolate_skips_missing_placeholders() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "keep: ((Missing.item))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                true,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());

            let output = std::fs::read_to_string(&output_path).unwrap();
            assert_eq!(output, "keep: ((Missing.item))\n");
        }

        #[tokio::test]
        async fn test_interpolate_fails_on_duplicate_item_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let sync_response = make_sync_response_with_logins(&[
                ("cipher-1", "MyLogin", "first-user", "first-pass"),
                ("cipher-2", "MyLogin", "second-user", "second-pass"),
            ]);
            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((MyLogin.username))\n").unwrap();

            let result = interpolate(
                input_path.to_str().unwrap(),
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            let err = result.unwrap_err().to_string();
            assert!(err.contains("Interpolation failed"));
            assert!(err.contains("MyLogin.username"));
            assert!(err.contains("item name 'MyLogin' is ambiguous"));
            assert!(err.contains("2 vault items match case-insensitively"));
        }

        #[tokio::test]
        async fn test_interpolate_fails_on_case_insensitive_duplicate_item_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let sync_response = make_sync_response_with_logins(&[
                ("cipher-1", "MyLogin", "first-user", "first-pass"),
                ("cipher-2", "mylogin", "second-user", "second-pass"),
            ]);
            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((MYLOGIN.username))\n").unwrap();

            let result = interpolate(
                input_path.to_str().unwrap(),
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            let err = result.unwrap_err().to_string();
            assert!(err.contains("item name 'MYLOGIN' is ambiguous"));
            assert!(err.contains("2 vault items match case-insensitively"));
        }

        #[tokio::test]
        async fn test_interpolate_allows_item_id_to_disambiguate_duplicate_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let sync_response = make_sync_response_with_logins(&[
                ("cipher-1", "MyLogin", "first-user", "first-pass"),
                ("cipher-2", "MyLogin", "second-user", "second-pass"),
            ]);
            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((cipher-2.username))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_ok());
            let output = std::fs::read_to_string(&output_path).unwrap();
            assert_eq!(output, "user: second-user\n");
        }

        #[tokio::test]
        async fn test_interpolate_skip_missing_leaves_ambiguous_placeholder_unchanged() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let sync_response = make_sync_response_with_logins(&[
                ("cipher-1", "MyLogin", "first-user", "first-pass"),
                ("cipher-2", "MyLogin", "second-user", "second-pass"),
            ]);
            mount_sync_response(&mock_server, sync_response).await;
            save_unlocked_test_config(&mock_server);

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((MyLogin.username))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                true,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_ok());
            let output = std::fs::read_to_string(&output_path).unwrap();
            assert_eq!(output, "user: ((MyLogin.username))\n");
        }
    }

    // Tests for list command
    mod list_tests {
        use super::*;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn make_encrypted_login(
            id: &str,
            name: &str,
            username: &str,
            password: &str,
            uri: &str,
            keys: &CryptoKeys,
        ) -> serde_json::Value {
            let enc_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                name.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_user = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                username.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_pass = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                password.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_uri = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                uri.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );

            serde_json::json!({
                "id": id,
                "type": 1,
                "name": enc_name,
                "login": {
                    "username": enc_user,
                    "password": enc_pass,
                    "uris": [{"uri": enc_uri, "match": 0}],
                    "totp": null
                },
                "collectionIds": [],
                "organizationId": null
            })
        }

        fn make_encrypted_note(id: &str, name: &str, keys: &CryptoKeys) -> serde_json::Value {
            let enc_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                name.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );

            serde_json::json!({
                "id": id,
                "type": 2,
                "name": enc_name,
                "secureNote": {},
                "collectionIds": [],
                "organizationId": null
            })
        }

        #[tokio::test]
        async fn test_list_no_filters_shows_all_items() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                    make_encrypted_note("cipher-2", "MyNote", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("type", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "object": "list",
                    "data": sync_response["ciphers"].clone()
                })))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = list(
                None,
                None,
                None,
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_with_type_filter() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                    make_encrypted_note("cipher-2", "MyNote", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("type", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "object": "list",
                    "data": sync_response["ciphers"].clone()
                })))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = list(
                Some("login".to_string()),
                None,
                None,
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_with_search_filter() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                    make_encrypted_login("cipher-2", "GitLab", "admin", "secret", "https://gitlab.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("type", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "object": "list",
                    "data": sync_response["ciphers"].clone()
                })))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = list(
                None,
                Some("hub".to_string()),
                None,
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_no_matches() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("type", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "object": "list",
                    "data": sync_response["ciphers"].clone()
                })))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = list(
                Some("note".to_string()),
                None,
                None,
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_invalid_type_filter_errors() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = list(
                Some("invalid".to_string()),
                None,
                None,
                None,
                false,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid type filter")
            );
        }
    }

    // Tests for get command
    mod get_tests {
        use super::*;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn make_encrypted_login(
            id: &str,
            name: &str,
            username: &str,
            password: &str,
            uri: &str,
            keys: &CryptoKeys,
        ) -> serde_json::Value {
            let enc_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                name.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_user = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                username.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_pass = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                password.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_uri = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                uri.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );

            serde_json::json!({
                "id": id,
                "type": 1,
                "name": enc_name,
                "login": {
                    "username": enc_user,
                    "password": enc_pass,
                    "uris": [{"uri": enc_uri, "match": 0}],
                    "totp": null
                },
                "collectionIds": [],
                "organizationId": null
            })
        }

        #[tokio::test]
        async fn test_get_by_id() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/ciphers/cipher-1"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(sync_response["ciphers"][0].clone()),
                )
                .expect(1)
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(0)
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "cipher-1",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_name() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "github",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_name_with_collection_filter_uses_filtered_ciphers() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let mut filtered_cipher = make_encrypted_login(
                "cipher-1",
                "GitHub",
                "user",
                "pass",
                "https://github.com",
                &keys,
            );
            filtered_cipher["collectionIds"] = serde_json::json!(["collection-1"]);
            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [
                    {
                        "id": "collection-1",
                        "name": "ignored-for-id-match",
                        "organizationId": "org-1"
                    }
                ],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });
            let ciphers_response = serde_json::json!({
                "object": "list",
                "data": [filtered_cipher]
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/ciphers"))
                .and(query_param("collectionId", "collection-1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&ciphers_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "github",
                "json",
                None,
                Some("collection-1".to_string()),
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok(), "{result:?}");
        }

        #[tokio::test]
        async fn test_get_does_not_fall_back_to_uri_match() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "Work Login", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "github.com",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not found"));
        }

        #[tokio::test]
        async fn test_get_fails_on_duplicate_item_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user-1", "pass-1", "https://github.com/one", &keys),
                    make_encrypted_login("cipher-2", "github", "user-2", "pass-2", "https://github.com/two", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let err = get(
                "github",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await
            .expect_err("duplicate item names should be ambiguous");

            let message = err.to_string();
            assert!(message.contains("item name 'github' is ambiguous"));
            assert!(message.contains("2 vault items match case-insensitively"));
        }

        #[tokio::test]
        async fn test_get_allows_id_to_disambiguate_duplicate_names() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user-1", "pass-1", "https://github.com/one", &keys),
                    make_encrypted_login("cipher-2", "github", "user-2", "pass-2", "https://github.com/two", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "cipher-2",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_not_found() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get(
                "missing",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not found"));
        }
    }

    // Tests for get_by_uri command
    mod get_by_uri_tests {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        fn make_encrypted_login(
            id: &str,
            name: &str,
            username: &str,
            password: &str,
            uri: &str,
            keys: &CryptoKeys,
        ) -> serde_json::Value {
            let enc_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                name.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_user = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                username.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_pass = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                password.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );
            let enc_uri = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                uri.as_bytes(),
                &keys.enc_key,
                &keys.mac_key,
            );

            serde_json::json!({
                "id": id,
                "type": 1,
                "name": enc_name,
                "login": {
                    "username": enc_user,
                    "password": enc_pass,
                    "uris": [{"uri": enc_uri, "match": 0}],
                    "totp": null
                },
                "collectionIds": [],
                "organizationId": null
            })
        }

        #[tokio::test]
        async fn test_get_by_uri_match() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "GitHub", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get_by_uri(
                "github.com",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_uri_matches_when_name_does_not_match() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [
                    make_encrypted_login("cipher-1", "Work Login", "user", "pass", "https://github.com", &keys),
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get_by_uri(
                "github.com",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    allow_plaintext_json: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_uri_not_found() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let sync_response = serde_json::json!({
                "ciphers": [],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            });

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .mount(&mock_server)
                .await;

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let result = get_by_uri(
                "missing.com",
                "json",
                None,
                None,
                &CommandOptions {
                    allow_insecure_http: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("No item found with URI containing")
            );
        }
    }

    // Tests for ensure_valid_token helper
    mod ensure_valid_token_tests {
        use super::*;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) -> config::ConfigDirOverride {
            Config::scoped_config_dir_override_for_thread(temp_dir.path().join("vaultwarden-cli"))
        }

        #[test]
        fn test_ensure_valid_token_errors_when_not_logged_in() {
            let _guard = tokio_test::block_on(ENV_LOCK.lock());
            let mut config = Config::default();
            let err = tokio_test::block_on(ensure_valid_token(&mut config, true)).unwrap_err();
            assert!(err.to_string().contains("Not logged in"));
        }

        #[test]
        fn test_ensure_valid_token_returns_token_when_not_expired() {
            let _guard = tokio_test::block_on(ENV_LOCK.lock());
            let mut config = Config {
                access_token: Some("valid-token".to_string()),
                token_expiry: Some(i64::MAX),
                ..Default::default()
            };
            let token = tokio_test::block_on(ensure_valid_token(&mut config, true)).unwrap();
            assert_eq!(token, "valid-token");
        }

        #[test]
        fn test_token_needs_refresh_with_negative_expiry() {
            let config = Config {
                token_expiry: Some(-1),
                ..Default::default()
            };

            assert!(token_needs_refresh(&config).unwrap());
        }

        #[test]
        fn test_token_needs_refresh_with_min_expiry() {
            let config = Config {
                token_expiry: Some(i64::MIN),
                ..Default::default()
            };

            assert!(token_needs_refresh(&config).unwrap());
        }

        #[test]
        fn test_token_needs_refresh_with_max_expiry() {
            let config = Config {
                token_expiry: Some(i64::MAX),
                ..Default::default()
            };

            assert!(!token_needs_refresh(&config).unwrap());
        }

        #[test]
        fn test_ensure_valid_token_errors_when_expired_without_refresh() {
            let _guard = tokio_test::block_on(ENV_LOCK.lock());
            let mut config = Config {
                access_token: Some("expired-token".to_string()), // secrets-ignore: test fixture
                token_expiry: Some(0),
                ..Default::default()
            };
            let err = tokio_test::block_on(ensure_valid_token(&mut config, true)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("Token expired. Please login again.")
            );
        }

        #[tokio::test]
        async fn test_ensure_valid_token_refreshes_successfully() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let response = serde_json::json!({
                "access_token": "new-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "new-refresh"
            });

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=old-refresh"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;

            let mut config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("expired-token".to_string()), // secrets-ignore: test fixture
                refresh_token: Some("old-refresh".to_string()),  // secrets-ignore: test fixture
                token_expiry: Some(0),
                ..Default::default()
            };

            let token = ensure_valid_token(&mut config, true).await.unwrap(); // secrets-ignore: test fixture
            assert_eq!(token, "new-token");
            assert_eq!(config.access_token, Some("new-token".to_string()));
            assert_eq!(config.refresh_token, Some("new-refresh".to_string()));
            assert!(config.token_expiry.unwrap() > 0);
        }

        #[tokio::test]
        async fn test_ensure_valid_token_serializes_concurrent_refresh() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;
            let response = serde_json::json!({
                "access_token": "new-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "new-refresh"
            });

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=old-refresh"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(&response)
                        .set_delay(std::time::Duration::from_millis(250)),
                )
                .expect(1)
                .mount(&mock_server)
                .await;

            let expired = Config {
                server: Some(mock_server.uri()),
                access_token: Some("expired-token".to_string()), // secrets-ignore: test fixture
                refresh_token: Some("old-refresh".to_string()),  // secrets-ignore: test fixture
                token_expiry: Some(0),
                ..Default::default()
            };
            expired.save().unwrap();

            let mut first = expired.clone();
            let mut second = expired;
            let (first_token, second_token) = tokio::join!(
                ensure_valid_token(&mut first, true),
                ensure_valid_token(&mut second, true)
            );

            assert_eq!(first_token.unwrap(), "new-token");
            assert_eq!(second_token.unwrap(), "new-token");
            assert_eq!(first.access_token, Some("new-token".to_string()));
            assert_eq!(second.access_token, Some("new-token".to_string()));
            assert_eq!(first.refresh_token, Some("new-refresh".to_string()));
            assert_eq!(second.refresh_token, Some("new-refresh".to_string()));
        }

        #[tokio::test]
        async fn test_ensure_valid_token_refresh_failure() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            let _config_dir_override = set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/identity/connect/token"))
                .respond_with(
                    ResponseTemplate::new(401).set_body_string("{\"error\":\"invalid_token\"}"),
                )
                .mount(&mock_server)
                .await;

            let mut config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("expired-token".to_string()), // secrets-ignore: test fixture
                refresh_token: Some("old-refresh".to_string()),  // secrets-ignore: test fixture
                token_expiry: Some(0),
                ..Default::default()
            };

            let err = ensure_valid_token(&mut config, true).await.unwrap_err();
            let display_chain = format!("{err:#}");
            assert!(
                err.to_string()
                    .contains("Token expired and refresh failed. Please login again.")
            );
            assert!(display_chain.contains("Token refresh failed (401 Unauthorized)"));
            assert!(display_chain.contains("invalid_token"));
        }
    }

    // Tests for get_cipher_keys helper
    mod get_cipher_keys_tests {
        use super::*;
        use crate::models::Cipher;

        fn create_minimal_cipher(org_id: Option<&str>) -> Cipher {
            Cipher {
                id: "test".to_string(),
                r#type: 1,
                organization_id: org_id.map(std::string::ToString::to_string),
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key: None,
                fields: None,
                data: None,
            }
        }

        #[test]
        fn test_get_cipher_keys_user_cipher() {
            let user_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };

            let config = Config {
                crypto_keys: Some(user_keys.clone()),
                ..Default::default()
            };

            let cipher = create_minimal_cipher(None);
            let keys = get_cipher_keys(&config, &cipher).unwrap();
            assert_eq!(keys.enc_key, user_keys.enc_key);
        }

        #[test]
        fn test_get_cipher_keys_org_cipher() {
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

            let cipher = create_minimal_cipher(Some("org-123"));
            let keys = get_cipher_keys(&config, &cipher).unwrap();
            assert_eq!(keys.enc_key, org_keys.enc_key);
        }

        #[test]
        fn test_get_cipher_keys_missing_org_keys() {
            let user_keys = CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            };

            let config = Config {
                crypto_keys: Some(user_keys),
                ..Default::default()
            };

            let cipher = create_minimal_cipher(Some("nonexistent-org"));
            let result = get_cipher_keys(&config, &cipher);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Organization key not available")
            );
        }

        #[test]
        fn test_get_cipher_keys_no_keys_at_all() {
            let config = Config::default();

            let cipher = create_minimal_cipher(None);
            let result = get_cipher_keys(&config, &cipher);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("No decryption keys")
            );
        }
    }

    mod output_helper_tests {
        use super::*;
        use tempfile::TempDir;

        fn sample_output() -> CipherOutput {
            CipherOutput {
                id: "cipher-1".to_string(),
                cipher_type: "login".to_string(),
                name: "My App".to_string(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                uri: Some("https://example.com".to_string()),
                notes: None,
                fields: Some(vec![
                    FieldOutput {
                        name: "api token".to_string(),
                        value: "tok-123".to_string(),
                        hidden: true,
                    },
                    FieldOutput {
                        name: "region".to_string(),
                        value: "us-east-1".to_string(),
                        hidden: false,
                    },
                ]),
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            }
        }

        #[test]
        fn test_resolve_component_errors_for_missing_standard_field() {
            let output = CipherOutput {
                username: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
                ..sample_output()
            };

            let err = resolve_component(&output, "username").unwrap_err();
            assert!(err.to_string().contains("Item has no username"));
        }

        #[test]
        fn test_resolve_component_errors_for_unknown_custom_field() {
            let err = resolve_component(&sample_output(), "missing-field").unwrap_err();
            assert!(
                err.to_string()
                    .contains("Item has no component 'missing-field'")
            );
        }

        #[test]
        fn test_format_list_output_json() {
            let output = sample_output();
            let out = format_list_output(&[output], true).unwrap();

            assert_eq!(out.len(), 1);
            assert!(out[0].starts_with('['));
            assert!(out[0].contains("\"id\": \"cipher-1\""));
            assert!(out[0].contains("\"type\": \"login\""));
            assert!(out[0].contains("\"name\": \"My App\""));
        }

        #[test]
        fn test_format_list_output_plain_env_vars() {
            let output = sample_output();
            let out = format_list_output(&[output], false).unwrap();

            assert_eq!(
                out,
                vec![
                    "MY_APP_URI".to_string(),
                    "MY_APP_USERNAME".to_string(),
                    "MY_APP_PASSWORD".to_string(),
                    "MY_APP_API_TOKEN".to_string(),
                    "MY_APP_REGION".to_string(),
                ]
            );
        }

        #[test]
        fn test_format_list_output_plain_env_vars_with_grouped_parents() {
            let mut first = sample_output();
            first.name = "GitHub".to_string();
            let mut second = sample_output();
            second.name = "my_note".to_string();
            second.uri = None;
            second.password = None;
            second.fields = None;

            let out = format_list_output(&[first, second], false).unwrap();

            assert_eq!(
                out,
                vec![
                    "GITHUB_URI".to_string(),
                    "GITHUB_USERNAME".to_string(),
                    "GITHUB_PASSWORD".to_string(),
                    "GITHUB_API_TOKEN".to_string(),
                    "GITHUB_REGION".to_string(),
                    String::new(),
                    "MY_NOTE_USERNAME".to_string(),
                ]
            );
        }

        #[test]
        fn test_format_list_output_plain_env_vars_includes_ssh_fields() {
            let output = CipherOutput {
                username: None,
                password: None,
                uri: None,
                fields: None,
                ssh_public_key: Some("ssh-rsa AAAA".to_string()),
                ssh_private_key: Some(
                    concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string(),
                ),
                ssh_fingerprint: Some("SHA256:abc123".to_string()),
                ..sample_output()
            };

            let out = format_list_output(&[output], false).unwrap();

            assert_eq!(
                out,
                vec![
                    "MY_APP_SSH_PUBLIC_KEY".to_string(),
                    "MY_APP_SSH_PRIVATE_KEY".to_string(),
                    "MY_APP_SSH_FINGERPRINT".to_string(),
                ]
            );
        }

        #[test]
        fn test_cipher_to_env_vars_includes_standard_and_custom_fields() {
            let vars = cipher_to_env_vars(&sample_output());

            assert_eq!(
                vars,
                vec![
                    ("MY_APP_URI".to_string(), "https://example.com".to_string()),
                    ("MY_APP_USERNAME".to_string(), "user".to_string()),
                    ("MY_APP_PASSWORD".to_string(), "pass".to_string()),
                    ("MY_APP_API_TOKEN".to_string(), "tok-123".to_string()),
                    ("MY_APP_REGION".to_string(), "us-east-1".to_string()),
                ]
            );
        }

        #[test]
        fn test_cipher_to_env_vars_includes_ssh_fields() {
            let output = CipherOutput {
                username: None,
                password: None,
                uri: None,
                fields: None,
                ssh_public_key: Some("ssh-rsa AAAA".to_string()),
                ssh_private_key: Some(
                    concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string(),
                ),
                ssh_fingerprint: Some("SHA256:abc123".to_string()),
                ..sample_output()
            };

            let vars = cipher_to_env_vars(&output);

            assert_eq!(
                vars,
                vec![
                    (
                        "MY_APP_SSH_PUBLIC_KEY".to_string(),
                        "ssh-rsa AAAA".to_string()
                    ),
                    (
                        "MY_APP_SSH_PRIVATE_KEY".to_string(),
                        concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----").to_string()
                    ),
                    (
                        "MY_APP_SSH_FINGERPRINT".to_string(),
                        "SHA256:abc123".to_string()
                    ),
                ]
            );
        }

        #[test]
        fn test_cipher_to_env_vars_skips_absent_standard_fields() {
            let output = CipherOutput {
                username: None,
                password: None,
                uri: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
                ..sample_output()
            };

            let vars = cipher_to_env_vars(&output);
            assert!(vars.is_empty());
        }

        #[test]
        fn test_write_interpolated_output_writes_to_file() {
            let temp_dir = TempDir::new().unwrap();
            let path = temp_dir.path().join("config.yml");

            write_interpolated_output("rendered: true\n", Some(path.to_str().unwrap())).unwrap();

            assert_eq!(fs::read_to_string(path).unwrap(), "rendered: true\n");
        }

        #[test]
        fn test_write_interpolated_output_reports_write_failure_context() {
            let temp_dir = TempDir::new().unwrap();
            let path = temp_dir.path().join("missing").join("config.yml");

            let err = write_interpolated_output("rendered: true\n", Some(path.to_str().unwrap()))
                .expect_err("write should fail when parent directory is absent");

            assert!(
                err.to_string()
                    .contains("Failed to write interpolated output to")
            );
            assert!(err.to_string().contains("missing/config.yml"));
        }

        #[test]
        fn test_format_unmatched_placeholder_warning_deduplicates_and_sorts() {
            let warning = format_unmatched_placeholder_warning(&[
                "((beta.password))".to_string(),
                "((alpha.username))".to_string(),
                "((beta.password))".to_string(),
            ])
            .unwrap();

            assert_eq!(
                warning,
                "Unmatched placeholders left unchanged:\n((alpha.username))\n((beta.password))"
            );
        }

        #[test]
        fn test_format_unmatched_placeholder_warning_returns_none_when_empty() {
            assert!(format_unmatched_placeholder_warning(&[]).is_none());
        }
    }

    mod print_cipher_output_tests {
        use super::*;

        fn sample_output() -> CipherOutput {
            CipherOutput {
                id: "cipher-1".to_string(),
                cipher_type: "login".to_string(),
                name: "My App".to_string(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                uri: Some("https://example.com".to_string()),
                notes: Some("notes".to_string()),
                fields: Some(vec![FieldOutput {
                    name: "api token".to_string(),
                    value: "tok-123".to_string(),
                    hidden: true,
                }]),
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            }
        }

        #[test]
        fn test_format_cipher_output_json() {
            let output = sample_output();
            let json = format_cipher_output(&output, "json").unwrap();
            assert!(json.contains("\"id\": \"cipher-1\""));
            assert!(json.contains("\"type\": \"login\""));
            assert!(json.contains("\"name\": \"My App\""));
            assert!(json.contains("\"username\": \"user\""));
        }

        #[test]
        fn test_format_cipher_output_env() {
            let output = sample_output();
            let env = format_cipher_output(&output, "env").unwrap();
            assert!(env.contains("export MY_APP_URI='https://example.com'\n"));
            assert!(env.contains("export MY_APP_USERNAME='user'\n"));
            assert!(env.contains("export MY_APP_PASSWORD='pass'\n"));
            assert!(env.contains("export MY_APP_API_TOKEN='tok-123'\n"));
        }

        #[test]
        fn test_format_cipher_output_env_uses_portable_names_for_edge_cases() {
            let output = CipherOutput {
                name: "123 café !!!".to_string(),
                fields: Some(vec![FieldOutput {
                    name: "9 token".to_string(),
                    value: "tok-123".to_string(),
                    hidden: true,
                }]),
                ..sample_output()
            };

            let env = format_cipher_output(&output, "env").unwrap();

            assert!(env.contains("export ITEM_123_CAF_USERNAME='user'\n"));
            assert!(env.contains("export ITEM_123_CAF_ITEM_9_TOKEN='tok-123'\n"));
        }

        #[test]
        #[cfg(unix)]
        fn test_format_cipher_output_env_edge_names_round_trip_through_shell() {
            let cases = [
                ("123 app", "ITEM_123_APP_PASSWORD"),
                ("日本語", "ITEM_PASSWORD"),
                ("!!!", "ITEM_PASSWORD"),
            ];

            for (item_name, env_name) in cases {
                let output = CipherOutput {
                    name: item_name.to_string(),
                    password: Some(format!("{item_name} secret")),
                    uri: None,
                    username: None,
                    fields: None,
                    ..sample_output()
                };
                let env = format_cipher_output(&output, "env").unwrap();
                let script = format!("{env}\nprintf %s \"${env_name}\"");

                let output = Command::new("sh").arg("-c").arg(script).output().unwrap();

                assert!(output.status.success());
                assert_eq!(output.stdout, format!("{item_name} secret").as_bytes());
            }
        }

        #[test]
        fn test_format_cipher_output_env_shell_quotes_sensitive_values() {
            let output = CipherOutput {
                password: Some("double \" dollar $ backslash \\ backtick `".to_string()),
                notes: Some("line one\nline two\rline three".to_string()),
                fields: Some(vec![FieldOutput {
                    name: "quote".to_string(),
                    value: "can't stop".to_string(),
                    hidden: true,
                }]),
                ..sample_output()
            };

            let env = format_cipher_output(&output, "env").unwrap();

            assert!(
                env.contains(
                    "export MY_APP_PASSWORD='double \" dollar $ backslash \\ backtick `'\n"
                )
            );
            assert!(env.contains("export MY_APP_QUOTE='can'\\''t stop'\n"));
        }

        #[test]
        fn test_format_cipher_output_env_preserves_multiline_values() {
            let output = CipherOutput {
                password: Some("line one\nline two\rline three".to_string()),
                fields: None,
                ..sample_output()
            };

            let env = format_cipher_output(&output, "env").unwrap();

            assert!(env.contains("export MY_APP_PASSWORD='line one\nline two\rline three'\n"));
        }

        #[test]
        fn test_format_cipher_output_env_rejects_nul_values() {
            let output = CipherOutput {
                password: Some("before\0after".to_string()),
                fields: None,
                ..sample_output()
            };

            let err = format_cipher_output(&output, "env").unwrap_err();

            assert!(
                err.to_string()
                    .contains("env output cannot represent values containing NUL bytes")
            );
        }

        #[test]
        fn test_cipher_to_env_vars_keeps_raw_values_for_direct_injection() {
            let raw = "line one\nline two\rquote ' dollar $ backslash \\ NUL \0 end";
            let output = CipherOutput {
                password: Some(raw.to_string()),
                fields: None,
                ..sample_output()
            };

            let vars = cipher_to_env_vars(&output);

            assert!(vars.contains(&("MY_APP_PASSWORD".to_string(), raw.to_string())));
        }

        #[test]
        fn test_format_cipher_output_value() {
            let output = sample_output();
            let value = format_cipher_output(&output, "value").unwrap();
            assert_eq!(value, "pass");
        }

        #[test]
        fn test_format_cipher_output_password_alias() {
            let output = sample_output();
            let value = format_cipher_output(&output, "password").unwrap();
            assert_eq!(value, "pass");
        }

        #[test]
        fn test_format_cipher_output_username() {
            let output = sample_output();
            let value = format_cipher_output(&output, "username").unwrap();
            assert_eq!(value, "user");
        }

        #[test]
        fn test_format_cipher_output_unknown_format() {
            let output = sample_output();
            let err = format_cipher_output(&output, "xml").unwrap_err();
            assert!(err.to_string().contains("Unknown format: xml"));
        }

        #[test]
        fn test_format_cipher_output_missing_password() {
            let output = CipherOutput {
                password: None,
                ..sample_output()
            };
            let err = format_cipher_output(&output, "value").unwrap_err();
            assert!(err.to_string().contains("Item has no password"));
        }

        #[test]
        fn test_format_cipher_output_missing_username() {
            let output = CipherOutput {
                username: None,
                ..sample_output()
            };
            let err = format_cipher_output(&output, "username").unwrap_err();
            assert!(err.to_string().contains("Item has no username"));
        }
    }

    mod plaintext_json_policy_tests {
        use super::*;

        #[test]
        fn allows_plaintext_json_when_stdout_is_terminal() {
            let opts = CommandOptions {
                json_stdout_is_terminal: true,
                ..Default::default()
            };

            ensure_plaintext_json_allowed(&opts).unwrap();
        }

        #[test]
        fn rejects_plaintext_json_when_stdout_is_captured_without_opt_in() {
            let err = ensure_plaintext_json_allowed(&CommandOptions::default()).unwrap_err();

            assert!(err.to_string().contains("Plaintext JSON output"));
            assert!(err.to_string().contains("--allow-plaintext-json"));
        }

        #[test]
        fn allows_plaintext_json_when_non_interactive_output_is_explicitly_enabled() {
            let opts = CommandOptions {
                allow_plaintext_json: true,
                ..Default::default()
            };

            ensure_plaintext_json_allowed(&opts).unwrap();
        }
    }
}
