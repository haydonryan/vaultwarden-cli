use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH}; // used by unix_now()

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs() as i64
}

use crate::api::ApiClient;
use crate::config::{self, Config};
use crate::crypto::CryptoKeys;
use crate::models::{Cipher, CipherOutput, CipherType, FieldOutput};

pub async fn login(
    server: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
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

    let api = ApiClient::new(&server)?;

    // Check server is reachable
    println!("Connecting to {}...", server);
    if !api.check_server().await? {
        anyhow::bail!("Server is not reachable");
    }

    // Perform login
    println!("Authenticating...");
    let token_response = api.login(&client_id, &client_secret).await?;

    // Calculate token expiry
    let expiry = unix_now() + token_response.expires_in;

    // Save configuration
    config.server = Some(server);
    config.client_id = Some(client_id.clone());
    config.access_token = Some(token_response.access_token.clone());
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(expiry);
    config.encrypted_key = token_response.key;
    config.kdf_iterations = token_response.kdf_iterations;
    config.save()?;

    // Fetch profile to get email for key derivation
    let sync_response = api.sync(&token_response.access_token).await?;
    config.email = Some(sync_response.profile.email.clone());
    config.encrypted_private_key = sync_response.profile.private_key.clone();

    // Store organization keys
    for org in &sync_response.profile.organizations {
        if let Some(key) = &org.key {
            config.org_keys.insert(org.id.clone(), key.clone());
        }
    }
    config.save()?;

    // Best-effort secure storage: some environments (headless/minimal Linux) don't provide
    // an activatable secret service over D-Bus.
    if let Err(err) = config::store_client_secret(&client_id, &client_secret) {
        eprintln!(
            "Warning: Could not store client secret in system keyring: {}",
            err
        );
        eprintln!(
            "You can keep using this session. If you need to login again later, pass --client-secret."
        );
    }

    println!("Login successful!");
    let org_count = config.org_keys.len();
    if org_count > 0 {
        println!("Found {} organization(s).", org_count);
    }
    println!("Run 'vaultwarden-cli unlock' to unlock the vault with your master password.");
    Ok(())
}

pub async fn unlock(password: Option<String>) -> Result<()> {
    let mut config = Config::load()?;

    if !config.is_logged_in() {
        anyhow::bail!("Not logged in. Please run 'vaultwarden-cli login' first.");
    }

    // Ensure token is still valid before prompting for password
    ensure_valid_token(&mut config).await?;

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
    let password = match password {
        Some(p) => p,
        None => {
            print!("Master password: ");
            io::stdout().flush()?;
            rpassword::read_password()?
        }
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
                            eprintln!("Warning: Failed to decrypt org {} key: {}", org_id, e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to decrypt private key: {}", e);
            }
        }
    }

    // Save the keys
    config.crypto_keys = Some(crypto_keys);
    config.save_keys()?;

    let org_count = config.org_crypto_keys.len();
    if org_count > 0 {
        println!(
            "Vault unlocked successfully! ({} organization keys decrypted)",
            org_count
        );
    } else {
        println!("Vault unlocked successfully!");
    }
    Ok(())
}

pub async fn lock() -> Result<()> {
    let config = Config::load()?;
    config.delete_saved_keys()?;
    println!("Vault locked.");
    Ok(())
}

pub async fn logout() -> Result<()> {
    let mut config = Config::load()?;

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
        println!("Server: {}", server);
    }
    if let Some(client_id) = &config.client_id {
        println!("Client ID: {}", client_id);
    }
    if let Some(email) = &config.email {
        println!("Email: {}", email);
    }

    // Check token expiry
    if let Some(expiry) = config.token_expiry {
        let now = unix_now();
        if expiry > now {
            let remaining = expiry - now;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            println!("Token expires in: {}h {}m", hours, minutes);
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

async fn ensure_valid_token(config: &mut Config) -> Result<String> {
    let access_token = config
        .access_token
        .clone()
        .context("Not logged in. Please run 'vaultwarden-cli login' first.")?;

    // Check if token is expired
    let now = unix_now();

    if let Some(expiry) = config.token_expiry {
        if now >= expiry - 60 {
            // Token expired or expiring soon, try to refresh
            if let Some(refresh_token) = &config.refresh_token {
                let api = ApiClient::from_config(config)?;
                match api.refresh_token(refresh_token).await {
                    Ok(token_response) => {
                        let new_expiry = now + token_response.expires_in;
                        config.access_token = Some(token_response.access_token.clone());
                        config.refresh_token = token_response.refresh_token;
                        config.token_expiry = Some(new_expiry);
                        config.save()?;
                        return Ok(token_response.access_token);
                    }
                    Err(_) => {
                        anyhow::bail!("Token expired and refresh failed. Please login again.");
                    }
                }
            } else {
                anyhow::bail!("Token expired. Please login again.");
            }
        }
    }

    Ok(access_token)
}

fn ensure_unlocked(config: &Config) -> Result<()> {
    if config.crypto_keys.is_none() {
        anyhow::bail!("Vault is locked. Please run 'vaultwarden-cli unlock' first.");
    }
    Ok(())
}

fn get_cipher_keys<'a>(config: &'a Config, cipher: &Cipher) -> Result<&'a CryptoKeys> {
    match config.get_keys_for_cipher(cipher.organization_id.as_deref()) {
        Some(keys) => Ok(keys),
        None => {
            if let Some(org_id) = &cipher.organization_id {
                anyhow::bail!(
                    "Organization key not available for org {}. Try re-logging in.",
                    org_id
                );
            }
            anyhow::bail!("No decryption keys available");
        }
    }
}

fn decrypt_cipher(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    // Get encrypted name
    let name = cipher.get_name().context("Cipher has no name")?;
    let decrypted_name = keys.decrypt_to_string(name)?;

    // Decrypt other fields if present
    let decrypted_username = cipher
        .get_username()
        .map(|u| keys.decrypt_to_string(u))
        .transpose()?;

    let decrypted_password = cipher
        .get_password()
        .map(|p| keys.decrypt_to_string(p))
        .transpose()?;

    let decrypted_uri = cipher
        .get_uri()
        .map(|u| keys.decrypt_to_string(u))
        .transpose()?;

    let decrypted_notes = cipher
        .get_notes()
        .map(|n| keys.decrypt_to_string(n))
        .transpose()?;

    let decrypted_fields = cipher.get_fields().map(|fields| {
        fields
            .iter()
            .filter_map(|f| {
                let name = f
                    .name
                    .as_ref()
                    .and_then(|n| keys.decrypt_to_string(n).ok())?;
                let value = f
                    .value
                    .as_ref()
                    .and_then(|v| keys.decrypt_to_string(v).ok())
                    .unwrap_or_default();
                Some(FieldOutput {
                    name,
                    value,
                    hidden: f.r#type == 1,
                })
            })
            .collect()
    });

    Ok(CipherOutput {
        id: cipher.id.clone(),
        cipher_type: cipher
            .cipher_type()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        name: decrypted_name,
        username: decrypted_username,
        password: decrypted_password,
        uri: decrypted_uri,
        notes: decrypted_notes,
        fields: decrypted_fields,
    })
}

fn resolve_org_id(profile: &crate::models::Profile, org_filter: &str) -> Result<String> {
    let matched = profile.organizations.iter().find(|o| {
        o.id == org_filter
            || o.name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(org_filter))
                .unwrap_or(false)
    });
    Ok(matched
        .with_context(|| format!("Organization '{}' not found", org_filter))?
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
        if let Some(oid) = org_id_filter {
            if col.organization_id != oid {
                continue;
            }
        }
        let keys = match config.get_keys_for_cipher(Some(&col.organization_id)) {
            Some(k) => k,
            None => continue,
        };
        if let Ok(name) = keys.decrypt_to_string(&col.name) {
            if name.eq_ignore_ascii_case(collection_filter) {
                return Ok(col.id.clone());
            }
        }
    }

    anyhow::bail!("Collection '{}' not found", collection_filter)
}

fn cipher_matches_filters(
    cipher: &Cipher,
    org_id_filter: Option<&str>,
    collection_id_filter: Option<&str>,
) -> bool {
    if let Some(oid) = org_id_filter {
        if cipher.organization_id.as_deref() != Some(oid) {
            return false;
        }
    }
    if let Some(cid) = collection_id_filter {
        if !cipher.collection_ids.iter().any(|id| id == cid) {
            return false;
        }
    }
    true
}

pub async fn list(
    type_filter: Option<String>,
    search: Option<String>,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Resolve org filter
    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&sync_response.profile, org))
        .transpose()?;

    // Resolve collection filter
    let collection_id_filter = collection_filter
        .as_deref()
        .map(|col| {
            resolve_collection_id(
                &sync_response.collections,
                col,
                org_id_filter.as_deref(),
                &config,
            )
        })
        .transpose()?;

    let mut ciphers: Vec<&Cipher> = sync_response
        .ciphers
        .iter()
        .filter(|c| {
            cipher_matches_filters(c, org_id_filter.as_deref(), collection_id_filter.as_deref())
        })
        .collect();

    // Apply type filter
    if let Some(type_str) = &type_filter {
        if let Ok(cipher_type) = CipherType::from_str(type_str) {
            ciphers.retain(|c| c.cipher_type() == Some(cipher_type));
        } else {
            anyhow::bail!(
                "Invalid type filter: {}. Use: login, note, card, identity",
                type_str
            );
        }
    }

    // Decrypt and filter
    let mut outputs: Vec<CipherOutput> = Vec::new();
    for cipher in ciphers {
        let keys = match get_cipher_keys(&config, cipher) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Warning: No keys for cipher {}: {}", cipher.id, e);
                continue;
            }
        };

        match decrypt_cipher(cipher, keys) {
            Ok(output) => {
                // Apply search filter on decrypted data
                if let Some(search_term) = &search {
                    let search_lower = search_term.to_lowercase();
                    let matches = output.name.to_lowercase().contains(&search_lower)
                        || output
                            .username
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&search_lower))
                            .unwrap_or(false)
                        || output
                            .uri
                            .as_ref()
                            .map(|u| u.to_lowercase().contains(&search_lower))
                            .unwrap_or(false);

                    if !matches {
                        continue;
                    }
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

    // Output as JSON array
    println!("{}", serde_json::to_string_pretty(&outputs)?);

    Ok(())
}

pub async fn get(
    item: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Resolve org filter
    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&sync_response.profile, org))
        .transpose()?;

    // Resolve collection filter
    let collection_id_filter = collection_filter
        .as_deref()
        .map(|col| {
            resolve_collection_id(
                &sync_response.collections,
                col,
                org_id_filter.as_deref(),
                &config,
            )
        })
        .transpose()?;

    let matches = |c: &Cipher| -> bool {
        cipher_matches_filters(c, org_id_filter.as_deref(), collection_id_filter.as_deref())
    };

    // Find the cipher by ID first
    let cipher = sync_response
        .ciphers
        .iter()
        .find(|c| c.id == item && matches(c));

    // If not found by ID, decrypt all and search by name/uri
    let output = if let Some(cipher) = cipher {
        let keys = get_cipher_keys(&config, cipher)?;
        decrypt_cipher(cipher, keys)?
    } else {
        // Search through decrypted ciphers
        let item_lower = item.to_lowercase();
        let mut found: Option<CipherOutput> = None;

        for cipher in &sync_response.ciphers {
            if !matches(cipher) {
                continue;
            }
            let keys = match get_cipher_keys(&config, cipher) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Ok(output) = decrypt_cipher(cipher, keys) {
                if output.name.to_lowercase() == item_lower
                    || output
                        .uri
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&item_lower))
                        .unwrap_or(false)
                {
                    found = Some(output);
                    break;
                }
            }
        }

        found.context(format!("Item '{}' not found", item))?
    };

    print_cipher_output(&output, format)
}

pub async fn get_by_uri(
    uri: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Resolve org filter
    let org_id_filter = org_filter
        .as_deref()
        .map(|org| resolve_org_id(&sync_response.profile, org))
        .transpose()?;

    // Resolve collection filter
    let collection_id_filter = collection_filter
        .as_deref()
        .map(|col| {
            resolve_collection_id(
                &sync_response.collections,
                col,
                org_id_filter.as_deref(),
                &config,
            )
        })
        .transpose()?;

    // Search through decrypted ciphers by URI
    let uri_lower = uri.to_lowercase();
    let mut found: Option<CipherOutput> = None;

    for cipher in &sync_response.ciphers {
        if !cipher_matches_filters(
            cipher,
            org_id_filter.as_deref(),
            collection_id_filter.as_deref(),
        ) {
            continue;
        }
        let keys = match get_cipher_keys(&config, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(output) = decrypt_cipher(cipher, keys) {
            if let Some(item_uri) = &output.uri {
                if item_uri.to_lowercase().contains(&uri_lower) {
                    found = Some(output);
                    break;
                }
            }
        }
    }

    let output = found.context(format!("No item found with URI containing '{}'", uri))?;

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
        _ => {
            if let Some(fields) = &output.fields {
                if let Some(field) = fields
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(component))
                {
                    return Ok(field.value.clone());
                }
            }
            anyhow::bail!("Item has no component '{}'", component);
        }
    }
}

pub async fn interpolate(file: &str, output_file: Option<&str>, skip_missing: bool) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;
    let mut by_name: HashMap<String, CipherOutput> = HashMap::new();

    for cipher in &sync_response.ciphers {
        let keys = match get_cipher_keys(&config, cipher) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(output) = decrypt_cipher(cipher, keys) {
            let key = output.name.to_lowercase();
            by_name.entry(key).or_insert(output);
        }
    }

    let input =
        fs::read_to_string(file).with_context(|| format!("Failed to read file '{}'", file))?;
    let re = Regex::new(r"\(\(([^\s()]+)\)\)").expect("valid regex");
    let mut missing: Vec<String> = Vec::new();

    let output = re.replace_all(&input, |caps: &regex::Captures| {
        let placeholder = &caps[1];
        match parse_placeholder(placeholder) {
            Ok((raw_name, component)) => {
                let key = raw_name.to_lowercase();
                match by_name.get(&key) {
                    Some(cipher) => match resolve_component(cipher, &component) {
                        Ok(value) => value,
                        Err(err) => {
                            if !skip_missing {
                                missing.push(format!("{}: {}", placeholder, err));
                            }
                            caps[0].to_string()
                        }
                    },
                    None => {
                        if !skip_missing {
                            missing.push(format!("{}: item '{}' not found", placeholder, raw_name));
                        }
                        caps[0].to_string()
                    }
                }
            }
            Err(err) => {
                if !skip_missing {
                    missing.push(format!("{}: {}", placeholder, err));
                }
                caps[0].to_string()
            }
        }
    });

    if !skip_missing && !missing.is_empty() {
        anyhow::bail!("Interpolation failed:\n{}", missing.join("\n"));
    }

    write_interpolated_output(&output, output_file)?;
    Ok(())
}

fn write_interpolated_output(output: &str, output_file: Option<&str>) -> Result<()> {
    match output_file {
        Some(path) => fs::write(path, output)
            .with_context(|| format!("Failed to write interpolated output to '{}'", path)),
        None => {
            print!("{}", output);
            Ok(())
        }
    }
}

fn cipher_to_env_vars(output: &CipherOutput) -> Vec<(String, String)> {
    let prefix = sanitize_env_name(&output.name);
    let mut vars: Vec<(String, String)> = Vec::new();
    if let Some(v) = &output.uri {
        vars.push((format!("{}_URI", prefix), v.clone()));
    }
    if let Some(v) = &output.username {
        vars.push((format!("{}_USERNAME", prefix), v.clone()));
    }
    if let Some(v) = &output.password {
        vars.push((format!("{}_PASSWORD", prefix), v.clone()));
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

fn print_cipher_output(output: &CipherOutput, format: &str) -> Result<()> {
    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(output)?);
        }
        "env" => {
            for (name, value) in cipher_to_env_vars(output) {
                println!("export {}=\"{}\"", name, escape_value(&value));
            }
        }
        "value" | "password" => {
            print!(
                "{}",
                output.password.as_deref().context("Item has no password")?
            );
        }
        "username" => {
            print!(
                "{}",
                output.username.as_deref().context("Item has no username")?
            );
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {}. Use: json, env, value, username",
                format
            );
        }
    }
    Ok(())
}

fn sanitize_env_name(name: &str) -> String {
    name.to_uppercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

fn escape_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

pub async fn run_with_secrets(
    item_or_uri: Option<&str>,
    search_by_uri: bool,
    org_filter: Option<&str>,
    folder_filter: Option<&str>,
    collection_filter: Option<&str>,
    info_only: bool,
    command: &[String],
) -> Result<()> {
    let requested_items: Vec<String> = if search_by_uri {
        Vec::new()
    } else {
        item_or_uri
            .map(|raw| {
                raw.split(',')
                    .map(|part| part.trim())
                    .filter(|part| !part.is_empty())
                    .map(|part| part.to_string())
                    .collect()
            })
            .unwrap_or_default()
    };

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
    if !search_by_uri && item_or_uri.is_some() && requested_items.is_empty() {
        anyhow::bail!("No item names provided.");
    }

    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Resolve org filter
    let org_id_filter = org_filter
        .map(|org| resolve_org_id(&sync_response.profile, org))
        .transpose()?;

    // Resolve folder_filter to a folder ID (folder names are encrypted)
    let folder_id_filter: Option<String> = if let Some(folder) = folder_filter {
        // Try exact ID match first
        if let Some(f) = sync_response.folders.iter().find(|f| f.id == folder) {
            Some(f.id.clone())
        } else {
            // Try decrypted name match using the user's vault key
            let user_keys = config.crypto_keys.as_ref().context("Vault locked")?;
            let matched = sync_response.folders.iter().find(|f| {
                user_keys
                    .decrypt_to_string(&f.name)
                    .ok()
                    .map(|n| n.eq_ignore_ascii_case(folder))
                    .unwrap_or(false)
            });
            Some(
                matched
                    .with_context(|| format!("Folder '{}' not found", folder))?
                    .id
                    .clone(),
            )
        }
    } else {
        None
    };

    // Resolve collection filter
    let collection_id_filter = collection_filter
        .map(|col| {
            resolve_collection_id(
                &sync_response.collections,
                col,
                org_id_filter.as_deref(),
                &config,
            )
        })
        .transpose()?;

    // Check whether a cipher passes the org/folder/collection filters
    let matches_filters = |cipher: &Cipher| -> bool {
        if let Some(ref oid) = org_id_filter {
            if cipher.organization_id.as_deref() != Some(oid.as_str()) {
                return false;
            }
        }
        if let Some(ref fid) = folder_id_filter {
            if cipher.folder_id.as_deref() != Some(fid.as_str()) {
                return false;
            }
        }
        if let Some(ref cid) = collection_id_filter {
            if !cipher.collection_ids.iter().any(|id| id == cid) {
                return false;
            }
        }
        true
    };

    let find_by_name_or_id = |name_or_id: &str| -> Result<CipherOutput> {
        // Search by ID first, then by name
        let cipher_by_id = sync_response
            .ciphers
            .iter()
            .find(|c| c.id == name_or_id && matches_filters(c));

        if let Some(cipher) = cipher_by_id {
            let keys = get_cipher_keys(&config, cipher)?;
            return decrypt_cipher(cipher, keys);
        }

        let item_lower = name_or_id.to_lowercase();
        let mut found: Option<CipherOutput> = None;

        for cipher in &sync_response.ciphers {
            if !matches_filters(cipher) {
                continue;
            }
            let keys = match get_cipher_keys(&config, cipher) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Ok(output) = decrypt_cipher(cipher, keys) {
                if output.name.to_lowercase() == item_lower {
                    found = Some(output);
                    break;
                }
            }
        }
        found.context(format!("Item '{}' not found", name_or_id))
    };

    // Find matching items
    let outputs: Vec<CipherOutput> = if search_by_uri {
        let uri = item_or_uri.expect("URI required for URI search");
        let uri_lower = uri.to_lowercase();
        let mut found: Option<CipherOutput> = None;

        for cipher in &sync_response.ciphers {
            if !matches_filters(cipher) {
                continue;
            }
            let keys = match get_cipher_keys(&config, cipher) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Ok(output) = decrypt_cipher(cipher, keys) {
                if let Some(item_uri) = &output.uri {
                    if item_uri.to_lowercase().contains(&uri_lower) {
                        found = Some(output);
                        break;
                    }
                }
            }
        }
        vec![found.context(format!("No item found with URI containing '{}'", uri))?]
    } else if !requested_items.is_empty() {
        requested_items
            .iter()
            .map(|name| find_by_name_or_id(name))
            .collect::<Result<Vec<_>>>()?
    } else {
        // No specific item requested — inject every item matching the scope filters.
        let outputs: Vec<CipherOutput> = sync_response
            .ciphers
            .iter()
            .filter(|cipher| matches_filters(cipher))
            .filter_map(|cipher| {
                let keys = get_cipher_keys(&config, cipher).ok()?;
                decrypt_cipher(cipher, keys).ok()
            })
            .collect();

        if outputs.is_empty() {
            anyhow::bail!("No item found matching the specified filters");
        }

        outputs
    };

    // Build environment variables from the ciphers
    let mut env_vars = Vec::new();
    for output in outputs {
        env_vars.extend(cipher_to_env_vars(&output));
    }

    // If --info flag, just print variable names
    if info_only {
        println!("Environment variables that would be injected:");
        for (name, _) in &env_vars {
            println!("  {}", name);
        }
        return Ok(());
    }

    // Require a command if not info_only
    if command.is_empty() {
        anyhow::bail!("No command specified. Use -- followed by the command to run.");
    }

    // Spawn the command with injected environment variables
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    // Inject secrets into environment
    for (name, value) in &env_vars {
        cmd.env(name, value);
    }

    // Run the command and wait for it to complete
    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute command: {}", command[0]))?;

    // Exit with the same code as the child process
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(sanitize_env_name("123app"), "123APP");
        }

        #[test]
        fn test_mixed_input() {
            assert_eq!(sanitize_env_name("My App-v2.0!"), "MY_APP_V2_0_");
        }

        #[test]
        fn test_already_valid_env_name() {
            assert_eq!(sanitize_env_name("MY_APP_NAME"), "MY_APP_NAME");
        }

        #[test]
        fn test_empty_string() {
            assert_eq!(sanitize_env_name(""), "");
        }

        #[test]
        fn test_unicode_characters() {
            // Note: is_alphanumeric() considers unicode letters as alphanumeric
            // So 'é' and CJK characters are preserved (uppercased where possible)
            let result = sanitize_env_name("café");
            assert!(result.starts_with("CAF"));
            // CJK characters don't have uppercase, so they stay as-is
            let result = sanitize_env_name("日本語");
            assert_eq!(result.chars().count(), 3); // 3 characters (not bytes)
        }

        #[test]
        fn test_consecutive_special_chars() {
            assert_eq!(sanitize_env_name("my--app"), "MY__APP");
            assert_eq!(sanitize_env_name("app...name"), "APP___NAME");
        }
    }

    // Tests for escape_value
    mod escape_value_tests {
        use super::*;

        #[test]
        fn test_no_escaping_needed() {
            assert_eq!(escape_value("simple"), "simple");
            assert_eq!(escape_value("hello world"), "hello world");
        }

        #[test]
        fn test_escape_backslash() {
            assert_eq!(escape_value("path\\to\\file"), "path\\\\to\\\\file");
        }

        #[test]
        fn test_escape_double_quote() {
            assert_eq!(escape_value("say \"hello\""), "say \\\"hello\\\"");
        }

        #[test]
        fn test_escape_dollar_sign() {
            assert_eq!(escape_value("$HOME"), "\\$HOME");
            assert_eq!(escape_value("cost: $100"), "cost: \\$100");
        }

        #[test]
        fn test_escape_backtick() {
            assert_eq!(escape_value("`command`"), "\\`command\\`");
        }

        #[test]
        fn test_multiple_escapes() {
            assert_eq!(
                escape_value("echo \"$HOME\" `pwd`"),
                "echo \\\"\\$HOME\\\" \\`pwd\\`"
            );
        }

        #[test]
        fn test_empty_string() {
            assert_eq!(escape_value(""), "");
        }

        #[test]
        fn test_complex_password() {
            // A realistic complex password with special characters
            assert_eq!(escape_value("P@ss\"word$123`!"), "P@ss\\\"word\\$123\\`!");
        }

        #[test]
        fn test_shell_injection_attempt() {
            // Ensure potential shell injection is safely escaped
            assert_eq!(escape_value("$(rm -rf /)"), "\\$(rm -rf /)");
            assert_eq!(escape_value("`rm -rf /`"), "\\`rm -rf /\\`");
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
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use cbc::Encryptor;
        use hmac::{Hmac, Mac};
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
                .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
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
                collection_ids: vec!["col-1".to_string()],
                fields: None,
                data: None,
            };

            assert!(cipher_matches_filters(&cipher, None, None));
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
                collection_ids: vec!["col-1".to_string(), "col-2".to_string()],
                fields: None,
                data: None,
            };

            assert!(cipher_matches_filters(
                &cipher,
                Some("org-1"),
                Some("col-2")
            ));
            assert!(!cipher_matches_filters(
                &cipher,
                Some("org-2"),
                Some("col-2")
            ));
            assert!(!cipher_matches_filters(
                &cipher,
                Some("org-1"),
                Some("col-9")
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
        use crate::models::Cipher;

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
                fields: None,
                data: None,
            }
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

    // Tests for get_cipher_keys helper
    mod get_cipher_keys_tests {
        use super::*;
        use crate::models::Cipher;

        fn create_minimal_cipher(org_id: Option<&str>) -> Cipher {
            Cipher {
                id: "test".to_string(),
                r#type: 1,
                organization_id: org_id.map(|s| s.to_string()),
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                login: None,
                card: None,
                identity: None,
                secure_note: None,
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
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Organization key not available"));
        }

        #[test]
        fn test_get_cipher_keys_no_keys_at_all() {
            let config = Config::default();

            let cipher = create_minimal_cipher(None);
            let result = get_cipher_keys(&config, &cipher);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No decryption keys"));
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
            }
        }

        #[test]
        fn test_resolve_component_errors_for_missing_standard_field() {
            let output = CipherOutput {
                username: None,
                ..sample_output()
            };

            let err = resolve_component(&output, "username").unwrap_err();
            assert!(err.to_string().contains("Item has no username"));
        }

        #[test]
        fn test_resolve_component_errors_for_unknown_custom_field() {
            let err = resolve_component(&sample_output(), "missing-field").unwrap_err();
            assert!(err
                .to_string()
                .contains("Item has no component 'missing-field'"));
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
        fn test_cipher_to_env_vars_skips_absent_standard_fields() {
            let output = CipherOutput {
                username: None,
                password: None,
                uri: None,
                fields: None,
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
    }
}
