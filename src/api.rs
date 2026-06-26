use crate::config::Config;
use crate::models::{CipherListResponse, SyncResponse, TokenResponse};
use anyhow::{Context, Result};
use reqwest::{Client, Response, Url};

const API_ERROR_BODY_LIMIT_BYTES: usize = 4096;

fn sanitize_error_body_snippet(body: &str) -> String {
    body.chars().flat_map(char::escape_default).collect()
}

async fn bounded_error_body_snippet(mut response: Response) -> String {
    let mut body = Vec::new();
    let mut truncated = false;

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = API_ERROR_BODY_LIMIT_BYTES.saturating_sub(body.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                if chunk.len() > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => return format!("<failed to read error response body: {err}>"),
        }
    }

    let snippet = String::from_utf8_lossy(&body);
    let sanitized = sanitize_error_body_snippet(&snippet);
    if truncated {
        format!("{sanitized} [truncated after {API_ERROR_BODY_LIMIT_BYTES} bytes]")
    } else {
        sanitized
    }
}

pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Result<Self> {
        Self::new_with_flags(base_url, false)
    }

    /// Create a new API client with explicit security flags.
    ///
    /// `allow_insecure_http`: if true, permit http:// URLs (CLI flag overrides env var).
    /// If false, falls back to the `VAULTWARDEN_ALLOW_HTTP` env var.
    pub fn new_with_flags(base_url: &str, allow_insecure_http: bool) -> Result<Self> {
        crate::install_rustls_crypto_provider();

        // Validate server URL scheme to prevent SSRF and credential leakage
        let trimmed = base_url.trim_end_matches('/');
        if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
            anyhow::bail!(
                "Invalid server URL: must start with https:// or http://. Got: {base_url}"
            );
        }
        if trimmed.starts_with("http://") {
            // CLI flag takes precedence; fall back to env var
            let allow_http = allow_insecure_http
                || std::env::var("VAULTWARDEN_ALLOW_HTTP")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            if !allow_http {
                anyhow::bail!(
                    "Insecure server URL rejected: only https:// is allowed in production. \
                     Got: {base_url}\n\
                     To permit http:// URLs, use --allow-insecure-http or set VAULTWARDEN_ALLOW_HTTP=1."
                );
            }
            eprintln!(
                "Warning: Using insecure HTTP connection. Secrets will be sent unencrypted. Use https:// in production."
            );
        }

        // Identify this client to the server. Some Bitwarden-compatible servers
        // (e.g. Vaultwarden) expect a `Bitwarden-Client-Version` header and log an
        // error for every request that omits it; the request still succeeds, but the
        // server's error log fills up. Send our crate version (a valid semver, which
        // such servers parse) plus a User-Agent — both sourced from Cargo.toml so they
        // track the crate with no hardcoded strings.
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            reqwest::header::HeaderName::from_static("bitwarden-client-version"),
            // `from_str` (not `from_static`) so a malformed version fails gracefully
            // through this constructor's `Result` instead of panicking at runtime.
            reqwest::header::HeaderValue::from_str(env!("CARGO_PKG_VERSION"))
                .context("CARGO_PKG_VERSION is not a valid HTTP header value")?,
        );

        let client = Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .default_headers(default_headers)
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Failed to create HTTP client")?;

        // Normalize base URL (remove trailing slash)
        let base_url = trimmed.to_string();

        Ok(Self { client, base_url })
    }

    pub fn from_config(config: &Config) -> Result<Self> {
        let server = config.get_server().context("No server configured")?;
        Self::new(server)
    }

    /// Create an API client from config with explicit security flags.
    pub fn from_config_with_flags(config: &Config, allow_insecure_http: bool) -> Result<Self> {
        let server = config.get_server().context("No server configured")?;
        Self::new_with_flags(server, allow_insecure_http)
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

    pub async fn ciphers(&self, access_token: &str) -> Result<CipherListResponse> {
        self.get_json(
            "/api/ciphers",
            access_token,
            "cipher list",
            "Cipher list",
            "Failed to parse cipher list response",
        )
        .await
    }

    pub async fn cipher_by_id(
        &self,
        access_token: &str,
        cipher_id: &str,
    ) -> Result<crate::models::Cipher> {
        let path = format!("/api/ciphers/{cipher_id}");
        self.get_json(
            &path,
            access_token,
            "cipher",
            "Cipher",
            "Failed to parse cipher response",
        )
        .await
    }

    pub async fn ciphers_filtered(
        &self,
        access_token: &str,
        organization_id: Option<&str>,
        collection_id: Option<&str>,
        cipher_type: Option<u8>,
    ) -> Result<CipherListResponse> {
        let mut params = Vec::new();
        if let Some(value) = organization_id {
            params.push(("organizationId", value.to_string()));
        }
        if let Some(value) = collection_id {
            params.push(("collectionId", value.to_string()));
        }
        if let Some(value) = cipher_type {
            params.push(("type", value.to_string()));
        }

        self.get_json_with_query(
            "/api/ciphers",
            &params,
            access_token,
            "filtered cipher list",
            "Filtered cipher list",
            "Failed to parse cipher list response",
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
            .with_context(|| format!("Failed to send {operation} request"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = bounded_error_body_snippet(response).await;
            anyhow::bail!("{error_prefix} failed ({status}): {body}");
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
        self.get_json_with_query(
            path,
            &[],
            access_token,
            operation,
            error_prefix,
            parse_context,
        )
        .await
    }

    async fn get_json_with_query<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        access_token: &str,
        operation: &str,
        error_prefix: &str,
        parse_context: &str,
    ) -> Result<T> {
        let mut url = Url::parse(&format!("{}{}", self.base_url, path))
            .context("Failed to build request URL")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            for (key, value) in query {
                query_pairs.append_pair(key, value);
            }
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .with_context(|| format!("Failed to send {operation} request"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = bounded_error_body_snippet(response).await;
            anyhow::bail!("{error_prefix} failed ({status}): {body}");
        }

        response
            .json::<T>()
            .await
            .with_context(|| parse_context.to_string())
    }
}
