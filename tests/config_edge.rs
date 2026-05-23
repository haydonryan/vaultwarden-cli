#![allow(clippy::pedantic, clippy::nursery)]

mod support;

use support::{TestContext, allow_insecure_key_file_fallback, env_lock};
use vaultwarden_cli::config::{self, Config};

#[test]
fn config_load_fails_for_invalid_config_json() {
    let ctx = TestContext::new();
    ctx.write_raw_config("{not-json").unwrap();

    let err = ctx.load_config().expect_err("config load should fail");

    assert!(err.to_string().contains("Failed to parse config"));
}

#[test]
fn config_load_ignores_invalid_saved_keys_json() {
    let ctx = TestContext::new();
    ctx.write_raw_config(
        r#"{
            "server": "https://vault.example.com"
        }"#,
    )
    .unwrap();
    ctx.write_raw_keys("{not-json").unwrap();

    let config = ctx.load_config().expect("config load should continue");

    assert_eq!(config.server.as_deref(), Some("https://vault.example.com"));
    assert!(config.crypto_keys.is_none());
    assert!(config.org_crypto_keys.is_empty());
}

#[test]
fn config_load_ignores_invalid_saved_key_base64() {
    let ctx = TestContext::new();
    ctx.write_raw_config(
        r#"{
            "server": "https://vault.example.com"
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

    let config = ctx.load_config().expect("config load should continue");

    assert_eq!(config.server.as_deref(), Some("https://vault.example.com"));
    assert!(config.crypto_keys.is_none());
    assert!(config.org_crypto_keys.is_empty());
}

#[test]
fn config_save_keys_fails_when_config_dir_is_missing() {
    let _guard = env_lock();
    let _allow_key_file = allow_insecure_key_file_fallback();
    let ctx = TestContext::new();

    let config = ctx.scoped_config(Config {
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        }),
        ..Default::default()
    });

    let err = config
        .save_keys()
        .expect_err("save_keys should fail without a config dir");

    assert!(err.to_string().contains("No such file"));
}

#[test]
fn config_save_keys_warns_when_client_id_is_none() {
    let _guard = env_lock();
    let _allow_key_file = allow_insecure_key_file_fallback();
    let ctx = TestContext::new();

    // Create the config directory so the file fallback can succeed —
    // we want to verify the *warning*, not the file-write failure.
    ctx.create_config_dir();

    let config = ctx.scoped_config(Config {
        // client_id deliberately absent: no keyring account can be formed
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        }),
        ..Default::default()
    });

    let _capture = config::capture_warnings();
    config
        .save_keys()
        .expect("save_keys should succeed via file fallback");
    let warnings = _capture.drain();

    assert!(
        warnings
            .iter()
            .any(|w| w.contains("client_id") && w.contains("not set")),
        "expected a warning about missing client_id, got: {warnings:?}"
    );
    // The explicit unsafe fallback path must also be mentioned.
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE")),
        "expected a warning mentioning the insecure key-file opt-in, got: {warnings:?}"
    );
}

#[test]
fn config_save_keys_defaults_to_no_persist_without_keyring() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.create_config_dir();

    let config = ctx.scoped_config(Config {
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![7u8; 32],
            mac_key: vec![9u8; 32],
        }),
        ..Default::default()
    });

    let _capture = config::capture_warnings();
    config
        .save_keys()
        .expect("no-persist key fallback should not fail");
    let warnings = _capture.drain();

    assert!(
        !ctx.keys_path().exists(),
        "keys.json should not be written unless insecure file fallback is explicit"
    );
    assert!(
        warnings.iter().any(|w| w.contains("not persisted")),
        "expected no-persist warning, got: {warnings:?}"
    );
}

#[test]
fn config_save_keys_round_trips_when_config_dir_exists() {
    let _guard = env_lock();
    let _allow_key_file = allow_insecure_key_file_fallback();
    let ctx = TestContext::new();

    let mut config = ctx.scoped_config(Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("token".to_string()),
        crypto_keys: Some(vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![1u8; 32],
            mac_key: vec![2u8; 32],
        }),
        ..Default::default()
    });
    config.org_crypto_keys.insert(
        "org-1".to_string(),
        vaultwarden_cli::crypto::CryptoKeys {
            enc_key: vec![3u8; 32],
            mac_key: vec![4u8; 32],
        },
    );

    config.save().unwrap();
    config.save_keys().unwrap();

    let loaded = ctx.load_config().unwrap();

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
    let _allow_key_file = allow_insecure_key_file_fallback();
    let ctx = TestContext::new();

    let mut config = ctx.scoped_config(Config {
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
    });
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

    let loaded = ctx.load_config().unwrap();
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

// ── Token storage tests ──────────────────────────────────────────────────────

#[test]
fn config_tokens_not_present_in_config_json_after_save() {
    let ctx = TestContext::new();

    let config = ctx.scoped_config(Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("secret-token-abc".to_string()),
        refresh_token: Some("refresh-token-xyz".to_string()),
        token_expiry: Some(9_999_999_999),
        ..Default::default()
    });
    config.save().unwrap();

    let raw = std::fs::read_to_string(ctx.config_path()).unwrap();
    assert!(
        !raw.contains("secret-token-abc"),
        "access_token must not appear in config.json: {raw}"
    );
    assert!(
        !raw.contains("refresh-token-xyz"),
        "refresh_token must not appear in config.json: {raw}"
    );
    assert!(
        !raw.contains("9999999999"),
        "token_expiry must not appear in config.json: {raw}"
    );
}

#[test]
fn config_save_load_round_trips_tokens() {
    let ctx = TestContext::new();

    let config = ctx.scoped_config(Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("round-trip-token".to_string()),
        refresh_token: Some("round-trip-refresh".to_string()),
        token_expiry: Some(1_234_567_890),
        ..Default::default()
    });
    // save() calls save_tokens() internally; with client_id=None it falls back
    // to tokens.json (same as save_keys falls back to keys.json).
    config.save().unwrap();

    let loaded = ctx.load_config().unwrap();
    assert_eq!(
        loaded.access_token.as_deref(),
        Some("round-trip-token"),
        "access_token should survive save/load"
    );
    assert_eq!(
        loaded.refresh_token.as_deref(),
        Some("round-trip-refresh"),
        "refresh_token should survive save/load"
    );
    assert_eq!(
        loaded.token_expiry,
        Some(1_234_567_890),
        "token_expiry should survive save/load"
    );
}

#[test]
fn config_save_tokens_noops_when_access_token_is_absent() {
    let ctx = TestContext::new();

    let config = ctx.scoped_config(Config {
        refresh_token: Some("refresh-without-access".to_string()),
        token_expiry: Some(1_234),
        ..Default::default()
    });

    config
        .save_tokens()
        .expect("save_tokens should no-op without an access token");

    assert!(
        !ctx.tokens_path().exists(),
        "tokens.json should not be created when there is no access token"
    );
}

#[test]
fn config_save_tokens_fails_when_config_dir_is_missing() {
    let ctx = TestContext::new();

    let config = ctx.scoped_config(Config {
        access_token: Some("token".to_string()),
        ..Default::default()
    });

    let err = config
        .save_tokens()
        .expect_err("save_tokens should fail without a config dir");

    assert!(err.to_string().contains("No such file"));
}

#[test]
fn config_load_ignores_invalid_saved_tokens_json() {
    let ctx = TestContext::new();
    ctx.write_raw_config(
        r#"{
            "server": "https://vault.example.com"
        }"#,
    )
    .unwrap();
    std::fs::write(ctx.tokens_path(), "{not-json").unwrap();

    let config = ctx.load_config().expect("config load should continue");

    assert_eq!(config.server.as_deref(), Some("https://vault.example.com"));
    assert!(config.access_token.is_none());
    assert!(config.refresh_token.is_none());
    assert!(config.token_expiry.is_none());
}

#[test]
fn config_load_saved_tokens_reports_malformed_file() {
    let ctx = TestContext::new();
    ctx.create_config_dir();
    std::fs::write(ctx.tokens_path(), "{not-json").unwrap();

    let mut config = Config::default().with_config_dir(ctx.config_dir());
    let err = config
        .load_saved_tokens()
        .expect_err("direct token load should report malformed persisted state");

    assert!(err.to_string().contains("line 1 column"));
}

#[test]
fn config_clear_removes_tokens() {
    let ctx = TestContext::new();

    let mut config = ctx.scoped_config(Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("to-be-cleared".to_string()),
        refresh_token: Some("refresh-to-be-cleared".to_string()),
        ..Default::default()
    });
    config.save().unwrap(); // persists tokens to tokens.json (no keyring in tests)

    assert!(
        ctx.tokens_path().exists(),
        "tokens.json should exist after save"
    );

    config.clear().unwrap();

    assert!(
        !ctx.tokens_path().exists(),
        "tokens.json should be removed after clear"
    );

    let loaded = ctx.load_config().unwrap();
    assert!(
        loaded.access_token.is_none(),
        "access_token should be absent after clear"
    );
    assert!(
        loaded.refresh_token.is_none(),
        "refresh_token should be absent after clear"
    );
}
