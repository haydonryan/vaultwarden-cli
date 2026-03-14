mod support;

use support::{env_lock, TestContext};
use vaultwarden_cli::config::Config;

#[test]
fn config_load_fails_for_invalid_config_json() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    ctx.write_raw_config("{not-json").unwrap();

    let err = Config::load().err().expect("config load should fail");

    assert!(err.to_string().contains("Failed to parse config"));
}

#[test]
fn config_load_ignores_invalid_saved_keys_json() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    ctx.write_raw_config(
        r#"{
            "server": "https://vault.example.com",
            "access_token": "token"
        }"#,
    )
    .unwrap();
    ctx.write_raw_keys("{not-json").unwrap();

    let config = Config::load().expect("config load should continue");

    assert_eq!(config.server.as_deref(), Some("https://vault.example.com"));
    assert_eq!(config.access_token.as_deref(), Some("token"));
    assert!(config.crypto_keys.is_none());
    assert!(config.org_crypto_keys.is_empty());
}

#[test]
fn config_load_ignores_invalid_saved_key_base64() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    ctx.write_raw_config(
        r#"{
            "server": "https://vault.example.com",
            "access_token": "token"
        }"#,
    )
    .unwrap();
    ctx.write_raw_keys(
        r#"{
            "user_keys": {
                "enc_key": "%%%not-base64%%%",
                "mac_key": "%%%not-base64%%%"
            },
            "org_keys": {}
        }"#,
    )
    .unwrap();

    let config = Config::load().expect("config load should continue");

    assert_eq!(config.server.as_deref(), Some("https://vault.example.com"));
    assert!(config.crypto_keys.is_none());
    assert!(config.org_crypto_keys.is_empty());
}
