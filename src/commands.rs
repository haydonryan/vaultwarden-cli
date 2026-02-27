use anyhow::{Context, Result};
use std::io::{self, Write};
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};  // used by unix_now()

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

pub async fn list(type_filter: Option<String>, search: Option<String>) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;
    let mut ciphers: Vec<&Cipher> = sync_response.ciphers.iter().collect();

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

pub async fn get(item: &str, format: &str) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Find the cipher by ID first
    let cipher = sync_response.ciphers.iter().find(|c| c.id == item);

    // If not found by ID, decrypt all and search by name/uri
    let output = if let Some(cipher) = cipher {
        let keys = get_cipher_keys(&config, cipher)?;
        decrypt_cipher(cipher, keys)?
    } else {
        // Search through decrypted ciphers
        let item_lower = item.to_lowercase();
        let mut found: Option<CipherOutput> = None;

        for cipher in &sync_response.ciphers {
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

pub async fn get_by_uri(uri: &str, format: &str) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Search through decrypted ciphers by URI
    let uri_lower = uri.to_lowercase();
    let mut found: Option<CipherOutput> = None;

    for cipher in &sync_response.ciphers {
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
    info_only: bool,
    command: &[String],
) -> Result<()> {
    if !search_by_uri && item_or_uri.is_none() && org_filter.is_none() && folder_filter.is_none() {
        anyhow::bail!("At least one of --credential-name, --org, or --folder must be specified.");
    }

    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Resolve org_filter to an org ID (org names are plaintext in the profile)
    let org_id_filter: Option<String> = if let Some(org) = org_filter {
        let matched = sync_response.profile.organizations.iter().find(|o| {
            o.id == org
                || o.name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(org))
                    .unwrap_or(false)
        });
        Some(
            matched
                .with_context(|| format!("Organization '{}' not found", org))?
                .id
                .clone(),
        )
    } else {
        None
    };

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

    // Check whether a cipher passes the org/folder filters
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
        true
    };

    // Find the item
    let output = if search_by_uri {
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
        found.context(format!("No item found with URI containing '{}'", uri))?
    } else if let Some(name_or_id) = item_or_uri {
        // Search by ID first, then by name
        let cipher_by_id = sync_response
            .ciphers
            .iter()
            .find(|c| c.id == name_or_id && matches_filters(c));

        if let Some(cipher) = cipher_by_id {
            let keys = get_cipher_keys(&config, cipher)?;
            decrypt_cipher(cipher, keys)?
        } else {
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
            found.context(format!("Item '{}' not found", name_or_id))?
        }
    } else {
        // No name specified — return the first item matching org/folder filters
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
                found = Some(output);
                break;
            }
        }
        found.context("No item found matching the specified filters")?
    };

    // Build environment variables from the cipher
    let env_vars = cipher_to_env_vars(&output);

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
}
