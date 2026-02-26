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
        let url = format!("{}/identity/connect/token", self.base_url);

        let params = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("deviceType", "14"), // CLI device type
            ("deviceIdentifier", "vaultwarden-cli"),
            ("deviceName", "Vaultwarden CLI"),
        ];

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("Failed to send login request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Login failed ({}): {}", status, body);
        }

        response
            .json::<TokenResponse>()
            .await
            .context("Failed to parse token response")
    }

    // Refresh access token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let url = format!("{}/identity/connect/token", self.base_url);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .await
            .context("Failed to send refresh request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Token refresh failed ({}): {}", status, body);
        }

        response
            .json::<TokenResponse>()
            .await
            .context("Failed to parse token response")
    }

    // Sync vault data
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let url = format!("{}/api/sync", self.base_url);

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to send sync request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Sync failed ({}): {}", status, body);
        }

        response
            .json::<SyncResponse>()
            .await
            .context("Failed to parse sync response")
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
}
