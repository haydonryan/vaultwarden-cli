mod support;

use support::{env_lock, TestContext};
use vaultwarden_cli::config::Config;

#[test]
fn config_load_fails_for_invalid_config_json() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    ctx.write_raw_config("{not-json").unwrap();

    let err = Config::load().expect_err("config load should fail");

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

#[test]
fn config_save_keys_fails_when_config_dir_is_missing() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();

    let config = Config {
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        }),
        ..Default::default()
    };

    let err = config
        .save_keys()
        .expect_err("save_keys should fail without a config dir");

    assert!(err.to_string().contains("No such file"));
}

#[test]
fn config_save_keys_round_trips_when_config_dir_exists() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();

    let mut config = Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("token".to_string()),
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![1u8; 32],
            mac_key: vec![2u8; 32],
        }),
        ..Default::default()
    };
    config.org_crypto_keys.insert(
        "org-1".to_string(),
        vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![3u8; 32],
            mac_key: vec![4u8; 32],
        },
    );

    config.save().unwrap();
    config.save_keys().unwrap();

    let loaded = Config::load().unwrap();

    let user_keys = loaded.crypto_keys.expect("user keys should load");
    assert_eq!(user_keys.enc_key, vec![1u8; 32]);
    assert_eq!(user_keys.mac_key, vec![2u8; 32]);

    let org_keys = loaded
        .org_crypto_keys
        .get("org-1")
        .expect("org keys should load");
    assert_eq!(org_keys.enc_key, vec![3u8; 32]);
    assert_eq!(org_keys.mac_key, vec![4u8; 32]);
}

#[test]
fn config_clear_removes_runtime_state_and_saved_keys_but_keeps_server_settings() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();

    let mut config = Config {
        server: Some("https://vault.example.com".to_string()),
        client_id: Some("client-id".to_string()),
        email: Some("user@example.com".to_string()),
        access_token: Some("token".to_string()),
        refresh_token: Some("refresh-token".to_string()),
        token_expiry: Some(12345),
        encrypted_key: Some("encrypted-key".to_string()),
        encrypted_private_key: Some("encrypted-private-key".to_string()),
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![1u8; 32],
            mac_key: vec![2u8; 32],
        }),
        ..Default::default()
    };
    config
        .org_keys
        .insert("org-1".to_string(), "encrypted-org-key".to_string());
    config.org_crypto_keys.insert(
        "org-1".to_string(),
        vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![3u8; 32],
            mac_key: vec![4u8; 32],
        },
    );

    config.save().unwrap();
    config.save_keys().unwrap();
    assert!(ctx.keys_path().exists());

    config.clear().unwrap();

    assert!(!ctx.keys_path().exists());

    let loaded = Config::load().unwrap();
    assert_eq!(loaded.server.as_deref(), Some("https://vault.example.com"));
    assert_eq!(loaded.client_id.as_deref(), Some("client-id"));
    assert_eq!(loaded.email.as_deref(), Some("user@example.com"));
    assert!(loaded.access_token.is_none());
    assert!(loaded.refresh_token.is_none());
    assert!(loaded.token_expiry.is_none());
    assert!(loaded.encrypted_key.is_none());
    assert!(loaded.encrypted_private_key.is_none());
    assert!(loaded.crypto_keys.is_none());
    assert!(loaded.org_keys.is_empty());
    assert!(loaded.org_crypto_keys.is_empty());
}
