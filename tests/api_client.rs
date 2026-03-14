mod support;

use support::TestContext;
use vaultwarden_cli::api::ApiClient;
use vaultwarden_cli::config::Config;
use wiremock::matchers::{method, path};
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
