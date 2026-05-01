#![allow(clippy::pedantic, clippy::nursery)]

mod support;

use support::TestContext;
use vaultwarden_cli::api::ApiClient;
use vaultwarden_cli::config::Config;
use vaultwarden_cli::models::CipherType;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn api_client_new_trims_trailing_slash_for_requests() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/alive"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&format!("{}/", mock_server.uri())).unwrap();

    let is_alive = client.check_server().await.unwrap();
    assert!(is_alive);
}

#[test]
fn api_client_from_config_requires_server() {
    let config = Config::default();

    let err = match ApiClient::from_config(&config) {
        Ok(_) => panic!("missing server"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("No server configured"));
}

#[tokio::test]
async fn api_client_from_config_uses_server_from_config() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/alive"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = Config {
        server: Some(mock_server.uri()),
        ..Default::default()
    };

    let client = ApiClient::from_config(&config).unwrap();

    let is_alive = client.check_server().await.unwrap();
    assert!(is_alive);
}

#[test]
fn support_test_context_builds_binary_command() {
    let ctx = TestContext::new();
    let _cmd = ctx.binary();
}

#[tokio::test]
async fn api_client_login_sends_expected_form_fields() {
    let mock_server = MockServer::start().await;
    let response = serde_json::json!({
        "access_token": "access-token",
        "expires_in": 3600,
        "token_type": "Bearer",
        "refresh_token": "refresh-token",
        "scope": "api",
        "Key": "2.encrypted-key",
        "KdfIterations": 600000
    });

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=api"))
        .and(body_string_contains("client_id=test-client"))
        .and(body_string_contains("client_secret=test-secret"))
        .and(body_string_contains("deviceType=14"))
        .and(body_string_contains("deviceIdentifier=vaultwarden-cli"))
        .and(body_string_contains("deviceName=Vaultwarden+CLI"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let token = client.login("test-client", "test-secret").await.unwrap();

    assert_eq!(token.access_token, "access-token");
    assert_eq!(token.refresh_token.as_deref(), Some("refresh-token"));
    assert_eq!(token.kdf_iterations, Some(600000));
}

#[tokio::test]
async fn api_client_login_surfaces_non_success_responses() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("{\"error\":\"invalid_grant\",\"detail\":\"bad client\"}"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .login("bad-client", "bad-secret")
        .await
        .expect_err("login should fail");

    let message = err.to_string();
    assert!(message.contains("Login failed (400 Bad Request)"));
    assert!(message.contains("invalid_grant"));
}

#[tokio::test]
async fn api_client_login_reports_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .login("test-client", "test-secret")
        .await
        .expect_err("parse should fail");

    assert!(err.to_string().contains("Failed to parse token response"));
}

#[tokio::test]
async fn api_client_refresh_token_sends_expected_form_fields() {
    let mock_server = MockServer::start().await;
    let response = serde_json::json!({
        "access_token": "new-access-token",
        "expires_in": 1800,
        "token_type": "Bearer",
        "refresh_token": "new-refresh-token"
    });

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=old-refresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let token = client.refresh_token("old-refresh-token").await.unwrap();

    assert_eq!(token.access_token, "new-access-token");
    assert_eq!(token.refresh_token.as_deref(), Some("new-refresh-token"));
    assert_eq!(token.expires_in, 1800);
}

#[tokio::test]
async fn api_client_refresh_token_surfaces_non_success_responses() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("{\"error\":\"invalid_token\"}"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .refresh_token("expired-refresh-token")
        .await
        .expect_err("refresh should fail");

    let message = err.to_string();
    assert!(message.contains("Token refresh failed (401 Unauthorized)"));
    assert!(message.contains("invalid_token"));
}

#[tokio::test]
async fn api_client_refresh_token_reports_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .refresh_token("refresh-token")
        .await
        .expect_err("parse should fail");

    assert!(err.to_string().contains("Failed to parse token response"));
}

#[tokio::test]
async fn api_client_sync_sends_bearer_token_and_parses_response() {
    let mock_server = MockServer::start().await;
    let response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": "2.encrypted-name",
                "Login": {
                    "Username": "2.encrypted-username",
                    "Password": "2.encrypted-password",
                    "Uris": [
                        { "Uri": "2.encrypted-uri", "Match": 0 }
                    ]
                }
            }
        ],
        "Folders": [],
        "Collections": [],
        "Profile": {
            "Id": "user-1",
            "Email": "user@example.com",
            "Organizations": []
        }
    });

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let sync = client.sync("access-token").await.unwrap();

    assert_eq!(sync.ciphers.len(), 1);
    assert_eq!(sync.profile.email, "user@example.com");
}

#[tokio::test]
async fn api_client_sync_surfaces_non_success_responses() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(403).set_body_string("{\"error\":\"forbidden\"}"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .sync("access-token")
        .await
        .expect_err("sync should fail");

    let message = err.to_string();
    assert!(message.contains("Sync failed (403 Forbidden)"));
    assert!(message.contains("forbidden"));
}

#[tokio::test]
async fn api_client_sync_reports_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let err = client
        .sync("access-token")
        .await
        .expect_err("parse should fail");

    assert!(err.to_string().contains("Failed to parse sync response"));
}

#[tokio::test]
async fn api_client_ciphers_sends_bearer_token_and_parses_response() {
    let mock_server = MockServer::start().await;
    let response = serde_json::json!({
        "object": "list",
        "data": [
            {
                "id": "cipher-ssh",
                "type": 5,
                "name": "2.encrypted-name",
                "sshKey": {
                    "privateKey": "2.encrypted-private-key",
                    "publicKey": "2.encrypted-public-key",
                    "fingerprint": "2.encrypted-fingerprint"
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let ciphers = client.ciphers("access-token").await.unwrap();

    assert_eq!(ciphers.data.len(), 1);
    assert_eq!(ciphers.data[0].id, "cipher-ssh");
    assert_eq!(ciphers.data[0].cipher_type(), Some(CipherType::SshKey));
    assert!(ciphers.data[0].ssh_key.is_some());
}

#[tokio::test]
async fn api_client_check_server_returns_false_for_non_success_status() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/alive"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = ApiClient::new(&mock_server.uri()).unwrap();
    let is_alive = client.check_server().await.unwrap();

    assert!(!is_alive);
}

#[tokio::test]
async fn api_client_check_server_reports_transport_errors() {
    let client = ApiClient::new("http://127.0.0.1:9").unwrap();

    let err = client
        .check_server()
        .await
        .expect_err("transport should fail");

    assert!(err.to_string().contains("Failed to check server status"));
}
