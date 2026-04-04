use anyhow::{Context, Result};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::str::FromStr;
use std::sync::LazyLock;
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

    if let Some(expiry) = config.token_expiry
        && now >= expiry - 60
    {
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

    Ok(access_token)
}

fn ensure_unlocked(config: &Config) -> Result<()> {
    if config.crypto_keys.is_none() {
        anyhow::bail!("Vault is locked. Please run 'vaultwarden-cli unlock' first.");
    }
    Ok(())
}

struct SyncContext {
    config: Config,
    sync_response: crate::models::SyncResponse,
}

async fn load_sync_context() -> Result<SyncContext> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;
    let mut sync_response = api.sync(&access_token).await?;
    if let Ok(cipher_list) = api.ciphers(&access_token).await {
        sync_response.ciphers = cipher_list.data;
    }
    Ok(SyncContext {
        config,
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

fn try_decrypt(keys: &CryptoKeys, encrypted: Option<&str>) -> Result<Option<String>> {
    encrypted.map(|e| keys.decrypt_to_string(e)).transpose()
}

fn decrypt_cipher(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    let name = cipher.get_name().context("Cipher has no name")?;
    let decrypted_name = keys.decrypt_to_string(name)?;

    let decrypted_username = try_decrypt(keys, cipher.get_username())?;
    let decrypted_password = try_decrypt(keys, cipher.get_password())?;
    let decrypted_uri = try_decrypt(keys, cipher.get_uri())?;
    let decrypted_notes = try_decrypt(keys, cipher.get_notes())?;

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

    // Decrypt SSH key fields if present
    let ssh_public_key = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.public_key.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());
    let ssh_private_key = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.private_key.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());
    let ssh_fingerprint = cipher
        .ssh_key
        .as_ref()
        .and_then(|s| s.fingerprint.as_deref())
        .and_then(|k| keys.decrypt_to_string(k).ok());

    Ok(CipherOutput {
        id: cipher.id.clone(),
        cipher_type: cipher
            .cipher_type()
            .map_or_else(|| "unknown".into(), |t| t.to_string()),
        name: decrypted_name,
        username: decrypted_username,
        password: decrypted_password,
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

    anyhow::bail!("Collection '{}' not found", collection_filter)
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
) -> Result<()> {
    let ctx = load_sync_context().await?;
    let (org_id_filter, collection_id_filter) = resolve_org_and_collection_filters(
        &ctx.sync_response,
        &ctx.config,
        org_filter.as_deref(),
        collection_filter.as_deref(),
    )?;

    let mut ciphers: Vec<&Cipher> = ctx
        .sync_response
        .ciphers
        .iter()
        .filter(|c| {
            cipher_matches_filters(
                c,
                org_id_filter.as_deref(),
                collection_id_filter.as_deref(),
                None,
            )
        })
        .collect();

    // Apply type filter (supports both type 5 and 6 for SSH keys)
    if let Some(type_str) = &type_filter {
        if let Ok(cipher_type) = CipherType::from_str(type_str) {
            ciphers.retain(|c| c.cipher_type() == Some(cipher_type));
        } else {
            anyhow::bail!(
                "Invalid type filter: {}. Use: login, note, card, identity, ssh",
                type_str
            );
        }
    }

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

        match decrypt_cipher(cipher, keys) {
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

    for line in format_list_output(&outputs, json_output)? {
        println!("{}", line);
    }

    Ok(())
}

fn format_list_output(outputs: &[CipherOutput], json_output: bool) -> Result<Vec<String>> {
    if json_output {
        return Ok(vec![serde_json::to_string_pretty(outputs)?]);
    }

    let mut lines: Vec<String> = Vec::new();
    for output in outputs {
        for (name, _) in cipher_to_env_vars(output) {
            lines.push(name);
        }
    }

    Ok(lines)
}

pub async fn get(
    item: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let ctx = load_sync_context().await?;
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

    let cipher = ctx
        .sync_response
        .ciphers
        .iter()
        .find(|c| c.id == item && matches(c));

    let output = if let Some(cipher) = cipher {
        let keys = get_cipher_keys(&ctx.config, cipher)?;
        decrypt_cipher(cipher, keys)?
    } else {
        let item_lower = item.to_lowercase();
        find_cipher_output(
            &ctx.sync_response.ciphers,
            &ctx.config,
            |o| {
                o.name.to_lowercase() == item_lower
                    || o.uri
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&item_lower))
                        .unwrap_or(false)
            },
            matches,
        )
        .context(format!("Item '{}' not found", item))?
    };

    print_cipher_output(&output, format)
}

pub async fn get_by_uri(
    uri: &str,
    format: &str,
    org_filter: Option<String>,
    collection_filter: Option<String>,
) -> Result<()> {
    let ctx = load_sync_context().await?;
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
                .map(|u| u.to_lowercase().contains(&uri_lower))
                .unwrap_or(false)
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
    .context(format!("No item found with URI containing '{}'", uri))?;

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
            anyhow::bail!("Item has no component '{}'", component);
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
        missing.push(format!("{}: {}", placeholder, error));
    }
    full.to_string()
}

pub async fn interpolate(file: &str, output_file: Option<&str>, skip_missing: bool) -> Result<()> {
    let ctx = load_sync_context().await?;
    let mut by_name: HashMap<String, CipherOutput> = HashMap::new();

    for cipher in &ctx.sync_response.ciphers {
        let keys = match get_cipher_keys(&ctx.config, cipher) {
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
    static PLACEHOLDER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\(\(([^\s()]+)\)\)").expect("valid regex"));
    let mut missing: Vec<String> = Vec::new();
    let mut unmatched_placeholders: Vec<String> = Vec::new();

    let output = PLACEHOLDER_RE.replace_all(&input, |caps: &regex::Captures| {
        let full_placeholder = caps[0].to_string();
        let placeholder = &caps[1];
        match parse_placeholder(placeholder) {
            Ok((raw_name, component)) => {
                let key = raw_name.to_lowercase();
                match by_name.get(&key) {
                    Some(cipher) => match resolve_component(cipher, &component) {
                        Ok(value) => value,
                        Err(err) => track_missing_placeholder(
                            placeholder,
                            &err.to_string(),
                            &full_placeholder,
                            skip_missing,
                            &mut missing,
                            &mut unmatched_placeholders,
                        ),
                    },
                    None => track_missing_placeholder(
                        placeholder,
                        &format!("item '{}' not found", raw_name),
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
        eprintln!("{}", warning);
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
    if let Some(v) = &output.ssh_public_key {
        vars.push((format!("{}_SSH_PUBLIC_KEY", prefix), v.clone()));
    }
    if let Some(v) = &output.ssh_private_key {
        vars.push((format!("{}_SSH_PRIVATE_KEY", prefix), v.clone()));
    }
    if let Some(v) = &output.ssh_fingerprint {
        vars.push((format!("{}_SSH_FINGERPRINT", prefix), v.clone()));
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
        .with_context(|| format!("Item has no {}", name))
        .map(|s| s.to_string())
}

fn format_cipher_output(output: &CipherOutput, format: &str) -> Result<String> {
    match format {
        "json" => Ok(serde_json::to_string_pretty(output)?),
        "env" => {
            let lines: String = cipher_to_env_vars(output)
                .into_iter()
                .map(|(name, value)| format!("export {}=\"{}\"\n", name, escape_value(&value)))
                .collect();
            Ok(lines)
        }
        "value" | "password" => get_field_string(&output.password, "password"),
        "username" => get_field_string(&output.username, "username"),
        _ => {
            anyhow::bail!(
                "Unknown format: {}. Use: json, env, value, username",
                format
            );
        }
    }
}

fn print_cipher_output(output: &CipherOutput, format: &str) -> Result<()> {
    let text = format_cipher_output(output, format)?;
    match format {
        "json" => println!("{}", text),
        _ => print!("{}", text),
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
    let mut result = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            result.push('\\');
        }
        result.push(c);
    }
    result
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

    let ctx = load_sync_context().await?;

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
        let cipher_by_id = ctx
            .sync_response
            .ciphers
            .iter()
            .find(|c| c.id == name_or_id && matches_filters(c));

        if let Some(cipher) = cipher_by_id {
            let keys = get_cipher_keys(&ctx.config, cipher)?;
            return decrypt_cipher(cipher, keys);
        }

        let item_lower = name_or_id.to_lowercase();
        find_cipher_output(
            &ctx.sync_response.ciphers,
            &ctx.config,
            |o| o.name.to_lowercase() == item_lower,
            matches_filters,
        )
        .context(format!("Item '{}' not found", name_or_id))
    };

    let outputs: Vec<CipherOutput> = if search_by_uri {
        let uri = item_or_uri.expect("URI required for URI search");
        let uri_lower = uri.to_lowercase();
        vec![
            find_cipher_output(
                &ctx.sync_response.ciphers,
                &ctx.config,
                |o| {
                    o.uri
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&uri_lower))
                        .unwrap_or(false)
                },
                matches_filters,
            )
            .context(format!("No item found with URI containing '{}'", uri))?,
        ]
    } else if !requested_items.is_empty() {
        requested_items
            .iter()
            .map(|name| find_by_name_or_id(name))
            .collect::<Result<Vec<_>>>()?
    } else {
        let outputs: Vec<CipherOutput> = ctx
            .sync_response
            .ciphers
            .iter()
            .filter(|cipher| matches_filters(cipher))
            .filter_map(|cipher| {
                let keys = get_cipher_keys(&ctx.config, cipher).ok()?;
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
    use tokio::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

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
        use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
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
                ssh_key: None,
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

            cipher.r#type = 5;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "ssh");

            cipher.r#type = 6;
            assert_eq!(cipher.cipher_type().unwrap().to_string(), "ssh");
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

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
        }

        #[tokio::test]
        async fn test_status_when_not_logged_in() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

            let result = status().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_status_when_logged_in_locked() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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
            set_temp_config_dir(&temp_dir);

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
            set_temp_config_dir(&temp_dir);

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
            set_temp_config_dir(&temp_dir);

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
        async fn test_logout_when_not_logged_in() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

            let result = logout().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_logout_clears_config_and_keys() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = logout().await;
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
    }

    // Tests for login command
    mod login_tests {
        use super::*;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
        }

        #[tokio::test]
        async fn test_login_success_with_provided_credentials() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

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
                .mount(&mock_server)
                .await;

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

            let result = login(
                Some(mock_server.uri()),
                Some("test-client".to_string()),
                Some("test-secret".to_string()),
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
            assert!(config.token_expiry.unwrap() > 0);
        }

        #[tokio::test]
        async fn test_login_fails_when_server_unreachable() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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
            set_temp_config_dir(&temp_dir);

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
            )
            .await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_login_uses_existing_config_server_and_client_id() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = login(None, None, Some("new-secret".to_string())).await;

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
        use rsa::rand_core::OsRng;
        use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
        use sha2::Sha256;

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
        }

        fn encrypt_symmetric_key_for_test(
            symmetric_key: &[u8],
            password: &str,
            email: &str,
            iterations: u32,
        ) -> String {
            use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
            use cbc::Encryptor;
            use hmac::{Hmac, Mac};

            type Aes256CbcEnc = Encryptor<aes::Aes256>;

            let master_key = CryptoKeys::derive_master_key(password, email, iterations);
            let stretched = CryptoKeys::stretch_master_key(&master_key).unwrap();

            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = symmetric_key.to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(&stretched.enc_key, &iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
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
            use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
            use cbc::Encryptor;
            use hmac::{Hmac, Mac};

            type Aes256CbcEnc = Encryptor<aes::Aes256>;

            let iv: Vec<u8> = (64u8..80).collect();
            let mut buf = plaintext.to_vec();
            let msg_len = buf.len();
            buf.resize(msg_len + 16, 0);

            let ciphertext = Aes256CbcEnc::new_from_slices(enc_key, &iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
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
            set_temp_config_dir(&temp_dir);

            let result = unlock(Some("password".to_string())).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Not logged in"));
        }

        #[tokio::test]
        async fn test_unlock_with_password_argument() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = unlock(Some("master-password".to_string())).await;
            assert!(result.is_ok());

            let loaded = Config::load().unwrap();
            assert!(loaded.is_unlocked());
            assert!(Config::keys_path().unwrap().exists());
        }

        #[tokio::test]
        async fn test_unlock_fails_with_wrong_password() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = unlock(Some("wrong-password".to_string())).await;
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
            set_temp_config_dir(&temp_dir);

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
            let mut rng = OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);
            let der = private_key.to_pkcs8_der().unwrap().as_bytes().to_vec();

            let encrypted_private_key =
                encrypt_bytes_for_test(&der, &user_keys.enc_key, &user_keys.mac_key);

            // Encrypt org symmetric key with RSA
            let org_symmetric_key: Vec<u8> = (0..64).collect();
            let padding = Oaep::new::<Sha256>();
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

            let result = unlock(Some("master-password".to_string())).await;
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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
        }

        fn make_sync_response_with_one_login() -> serde_json::Value {
            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let encrypted_name = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                b"MyLogin",
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            );
            let encrypted_user = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                b"myuser",
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            );
            let encrypted_pass = crate::crypto::tests::test_helpers::encrypt_bytes_for_test(
                b"mypass",
                &crypto_keys.enc_key,
                &crypto_keys.mac_key,
            );

            serde_json::json!({
                "ciphers": [
                    {
                        "id": "cipher-1",
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
                    }
                ],
                "folders": [],
                "collections": [],
                "profile": {
                    "id": "user-1",
                    "email": "user@example.com",
                    "organizations": []
                }
            })
        }

        #[tokio::test]
        async fn test_interpolate_replaces_placeholders() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(crypto_keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(
                &input_path,
                "user: ((MyLogin.username))\npass: ((MyLogin.password))\n",
            )
            .unwrap();

            let result = interpolate(input_path.to_str().unwrap(), None, false).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_interpolate_writes_to_output_file() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(crypto_keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "user: ((MyLogin.username))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                false,
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
            set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(crypto_keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "missing: ((Unknown.item))\n").unwrap();

            let result = interpolate(input_path.to_str().unwrap(), None, false).await;
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
            set_temp_config_dir(&temp_dir);

            let mock_server = MockServer::start().await;

            let sync_response = make_sync_response_with_one_login();

            Mock::given(method("GET"))
                .and(path("/api/sync"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
                .expect(1)
                .mount(&mock_server)
                .await;

            let crypto_keys = CryptoKeys {
                enc_key: vec![0x42u8; 32],
                mac_key: vec![0x43u8; 32],
            };

            let config = Config {
                server: Some(mock_server.uri()),
                access_token: Some("token".to_string()),
                token_expiry: Some(i64::MAX),
                email: Some("user@example.com".to_string()),
                crypto_keys: Some(crypto_keys),
                ..Default::default()
            };
            config.save().unwrap();
            config.save_keys().unwrap();

            let input_path = temp_dir.path().join("input.yml");
            std::fs::write(&input_path, "keep: ((Missing.item))\n").unwrap();

            let output_path = temp_dir.path().join("output.yml");
            let result = interpolate(
                input_path.to_str().unwrap(),
                Some(output_path.to_str().unwrap()),
                true,
            )
            .await;
            assert!(result.is_ok());

            let output = std::fs::read_to_string(&output_path).unwrap();
            assert_eq!(output, "keep: ((Missing.item))\n");
        }
    }

    // Tests for list command
    mod list_tests {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
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
            set_temp_config_dir(&temp_dir);

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

            let result = list(None, None, None, None, false).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_with_type_filter() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = list(Some("login".to_string()), None, None, None, false).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_with_search_filter() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = list(None, Some("hub".to_string()), None, None, false).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_no_matches() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = list(Some("note".to_string()), None, None, None, false).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_list_invalid_type_filter_errors() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = list(Some("invalid".to_string()), None, None, None, false).await;
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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
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
            set_temp_config_dir(&temp_dir);

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

            let result = get("cipher-1", "json", None, None).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_name() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = get("github", "json", None, None).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_not_found() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = get("missing", "json", None, None).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not found"));
        }
    }

    // Tests for get_by_uri command
    mod get_by_uri_tests {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
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
            set_temp_config_dir(&temp_dir);

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

            let result = get_by_uri("github.com", "json", None, None).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_get_by_uri_not_found() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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

            let result = get_by_uri("missing.com", "json", None, None).await;
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

        fn set_temp_config_dir(temp_dir: &tempfile::TempDir) {
            unsafe {
                std::env::set_var("HOME", temp_dir.path());
                std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());
            }
        }

        #[test]
        fn test_ensure_valid_token_errors_when_not_logged_in() {
            let _guard = tokio_test::block_on(ENV_LOCK.lock());
            let mut config = Config::default();
            let err = tokio_test::block_on(ensure_valid_token(&mut config)).unwrap_err();
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
            let token = tokio_test::block_on(ensure_valid_token(&mut config)).unwrap();
            assert_eq!(token, "valid-token");
        }

        #[test]
        fn test_ensure_valid_token_errors_when_expired_without_refresh() {
            let _guard = tokio_test::block_on(ENV_LOCK.lock());
            let mut config = Config {
                access_token: Some("expired-token".to_string()),
                token_expiry: Some(0),
                ..Default::default()
            };
            let err = tokio_test::block_on(ensure_valid_token(&mut config)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("Token expired. Please login again.")
            );
        }

        #[tokio::test]
        async fn test_ensure_valid_token_refreshes_successfully() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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
                access_token: Some("expired-token".to_string()),
                refresh_token: Some("old-refresh".to_string()),
                token_expiry: Some(0),
                ..Default::default()
            };

            let token = ensure_valid_token(&mut config).await.unwrap();
            assert_eq!(token, "new-token");
            assert_eq!(config.access_token, Some("new-token".to_string()));
            assert_eq!(config.refresh_token, Some("new-refresh".to_string()));
            assert!(config.token_expiry.unwrap() > 0);
        }

        #[tokio::test]
        async fn test_ensure_valid_token_refresh_failure() {
            let _guard = ENV_LOCK.lock().await;
            let temp_dir = tempfile::TempDir::new().unwrap();
            set_temp_config_dir(&temp_dir);

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
                access_token: Some("expired-token".to_string()),
                refresh_token: Some("old-refresh".to_string()),
                token_expiry: Some(0),
                ..Default::default()
            };

            let err = ensure_valid_token(&mut config).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("Token expired and refresh failed. Please login again.")
            );
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
            assert!(env.contains("export MY_APP_URI=\"https://example.com\"\n"));
            assert!(env.contains("export MY_APP_USERNAME=\"user\"\n"));
            assert!(env.contains("export MY_APP_PASSWORD=\"pass\"\n"));
            assert!(env.contains("export MY_APP_API_TOKEN=\"tok-123\"\n"));
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
}
