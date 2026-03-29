use crate::config::Config;
use crate::models::{SyncResponse, TokenResponse};
use anyhow::{Context, Result};
use reqwest::Client;

pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .context("Failed to create HTTP client")?;

        // Normalize base URL (remove trailing slash)
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self { client, base_url })
    }

    pub fn from_config(config: &Config) -> Result<Self> {
        let server = config.get_server().context("No server configured")?;
        Self::new(server)
    }

    // OAuth2 token endpoint using client credentials
    pub async fn login(&self, client_id: &str, client_secret: &str) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("deviceType", "14"), // CLI device type
            ("deviceIdentifier", "vaultwarden-cli"),
            ("deviceName", "Vaultwarden CLI"),
        ];

        self.post_form(
            "/identity/connect/token",
            &params,
            "login",
            "Login",
            "Failed to parse token response",
        )
        .await
    }

    // Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        self.post_form(
            "/identity/connect/token",
            &params,
            "token refresh",
            "Token refresh",
            "Failed to parse token response",
        )
        .await
    }

    // Sync vault data
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        self.get_json(
            "/api/sync",
            access_token,
            "sync",
            "Sync",
            "Failed to parse sync response",
        )
        .await
    }

    // Check server status/health
    pub async fn check_server(&self) -> Result<bool> {
        let url = format!("{}/alive", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to check server status")?;

        Ok(response.status().is_success())
    }

    async fn post_form<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .post(&url)
            .form(params)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("{} failed ({}): {}", error_prefix, status, body);
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        access_token: &str,
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .with_context(|| format!("Failed to send {} request", operation))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("{} failed ({}): {}", error_prefix, status, body);
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }
}
