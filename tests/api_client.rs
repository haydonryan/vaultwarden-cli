mod support;

use support::TestContext;
use vaultwarden_cli::api::ApiClient;
use vaultwarden_cli::config::Config;
use wiremock::matchers::{body_string_contains, method, path};
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

    let err = ApiClient::from_config(&config).err().expect("missing server");
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
        .err()
        .expect("login should fail");

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
        .err()
        .expect("parse should fail");

    assert!(err.to_string().contains("Failed to parse token response"));
}
