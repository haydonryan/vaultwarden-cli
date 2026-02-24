use anyhow::{Context, Result};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry = now + token_response.expires_in;

    // Save configuration
    config.server = Some(server);
    config.client_id = Some(client_id.clone());
    config.access_token = Some(token_response.access_token.clone());
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(expiry);
    config.encrypted_key = token_response.key;
    config.kdf_iterations = token_response.kdf_iterations;
    config.save()?;

    // Store client secret securely
    config::store_client_secret(&client_id, &client_secret)?;

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

    let email = config.email.as_ref()
        .context("Email not found. Please login again.")?;
    let encrypted_key = config.encrypted_key.as_ref()
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
        println!("Vault unlocked successfully! ({} organization keys decrypted)", org_count);
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
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
    let access_token = config.access_token.clone()
        .context("Not logged in. Please run 'vaultwarden-cli login' first.")?;

    // Check if token is expired
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

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
            if cipher.organization_id.is_some() {
                anyhow::bail!(
                    "Organization key not available for org {}. Try re-logging in.",
                    cipher.organization_id.as_ref().unwrap()
                );
            }
            anyhow::bail!("No decryption keys available");
        }
    }
}

fn decrypt_cipher(cipher: &Cipher, keys: &CryptoKeys) -> Result<CipherOutput> {
    // Get encrypted name
    let name = cipher.get_name()
        .context("Cipher has no name")?;
    let decrypted_name = keys.decrypt_to_string(name)?;

    // Decrypt other fields if present
    let decrypted_username = cipher.get_username()
        .map(|u| keys.decrypt_to_string(u))
        .transpose()?;

    let decrypted_password = cipher.get_password()
        .map(|p| keys.decrypt_to_string(p))
        .transpose()?;

    let decrypted_uri = cipher.get_uri()
        .map(|u| keys.decrypt_to_string(u))
        .transpose()?;

    let decrypted_notes = cipher.get_notes()
        .map(|n| keys.decrypt_to_string(n))
        .transpose()?;

    let decrypted_fields = cipher.get_fields()
        .map(|fields| {
            fields.iter()
                .filter_map(|f| {
                    let name = f.name.as_ref()
                        .and_then(|n| keys.decrypt_to_string(n).ok())?;
                    let value = f.value.as_ref()
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
        cipher_type: cipher.cipher_type()
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

pub async fn list(
    type_filter: Option<String>,
    search: Option<String>,
) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    ensure_unlocked(&config)?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;
    let mut ciphers: Vec<&Cipher> = sync_response.ciphers.iter().collect();

    // Apply type filter
    if let Some(type_str) = &type_filter {
        if let Some(cipher_type) = CipherType::from_str(type_str) {
            ciphers.retain(|c| c.cipher_type() == Some(cipher_type));
        } else {
            anyhow::bail!("Invalid type filter: {}. Use: login, note, card, identity", type_str);
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
                        || output.username.as_ref()
                            .map(|u| u.to_lowercase().contains(&search_lower))
                            .unwrap_or(false)
                        || output.uri.as_ref()
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
    let cipher = sync_response.ciphers.iter()
        .find(|c| c.id == item);

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
                    || output.uri.as_ref()
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

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "env" => {
            // Output as environment variable exports
            let name_upper = sanitize_env_name(&output.name);
            if let Some(username) = &output.username {
                println!("export {}_USERNAME=\"{}\"", name_upper, escape_value(username));
            }
            if let Some(password) = &output.password {
                println!("export {}_PASSWORD=\"{}\"", name_upper, escape_value(password));
            }
            if let Some(fields) = &output.fields {
                for field in fields {
                    let field_name = sanitize_env_name(&field.name);
                    println!("export {}_{}=\"{}\"", name_upper, field_name, escape_value(&field.value));
                }
            }
        }
        "value" | "password" => {
            // Output just the password value
            if let Some(password) = &output.password {
                print!("{}", password);
            } else {
                anyhow::bail!("Item has no password");
            }
        }
        "username" => {
            if let Some(username) = &output.username {
                print!("{}", username);
            } else {
                anyhow::bail!("Item has no username");
            }
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use: json, env, value, username", format);
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
