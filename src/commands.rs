use anyhow::{Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::ApiClient;
use crate::config::{self, Config};
use crate::models::{Cipher, CipherOutput, CipherType};

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
        .context("Client ID is required. Use --client_id.")?;
    let client_secret = client_secret
        .or_else(|| config::get_client_secret(&client_id).ok())
        .context("Client secret is required. Use --client_secret.")?;

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
    config.access_token = Some(token_response.access_token);
    config.refresh_token = token_response.refresh_token;
    config.token_expiry = Some(expiry);
    config.save()?;

    // Store client secret securely
    config::store_client_secret(&client_id, &client_secret)?;

    println!("Login successful!");
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

pub async fn list(
    type_filter: Option<String>,
    search: Option<String>,
) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
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

    // Apply search filter
    if let Some(search_term) = &search {
        ciphers.retain(|c| c.matches_search(search_term));
    }

    if ciphers.is_empty() {
        println!("No items found.");
        return Ok(());
    }

    // Output as JSON array
    let outputs: Vec<CipherOutput> = ciphers.iter().map(|c| CipherOutput::from(*c)).collect();
    println!("{}", serde_json::to_string_pretty(&outputs)?);

    Ok(())
}

pub async fn get(item: &str, format: &str) -> Result<()> {
    let mut config = Config::load()?;
    let access_token = ensure_valid_token(&mut config).await?;
    let api = ApiClient::from_config(&config)?;

    let sync_response = api.sync(&access_token).await?;

    // Find the cipher by ID or name
    let cipher = sync_response.ciphers.iter()
        .find(|c| c.id == item || c.name.to_lowercase() == item.to_lowercase())
        .or_else(|| {
            // Also search by URI
            sync_response.ciphers.iter().find(|c| c.matches_search(item))
        })
        .context(format!("Item '{}' not found", item))?;

    let output = CipherOutput::from(cipher);

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
                    println!("export {}_{} =\"{}\"", name_upper, field_name, escape_value(&field.value));
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
