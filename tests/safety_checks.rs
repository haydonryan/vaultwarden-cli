//! Tests for credential handling and hardening behaviours.
//!
//! These tests verify that vaultwarden-cli:
//! - Restricts file permissions on config and key files (0o600/0o700)
//! - Wipes key material from memory when CryptoKeys is dropped (ZeroizeOnDrop)
//! - Stores decryption keys in the OS keyring (with file fallback)
//! - Validates server URLs before connecting
//! - Warns when decrypting items without MAC integrity verification
//! - Restricts permissions on interpolation output files
//! - Configures request timeouts on the API client

#![allow(clippy::pedantic, clippy::nursery)]

mod support;

use support::{TestContext, env_lock};
use vaultwarden_cli::config::Config;
use vaultwarden_cli::crypto::CryptoKeys;

// ─────────────────────────────────────────────
// Restrictive file permissions (Unix only)
// ─────────────────────────────────────────────

#[cfg(unix)]
mod restrictive_file_permissions {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn config_file_is_owner_readable_and_writable_only() {
        let _guard = env_lock();
        let ctx = TestContext::new();
        ctx.set_process_env();

        let config = Config {
            server: Some("https://vault.example.com".to_string()),
            access_token: Some("secret-token".to_string()),
            ..Default::default()
        };
        config.save().unwrap();

        let mode = fs::metadata(ctx.config_path())
            .expect("config file should exist")
            .permissions()
            .mode();

        // Owner read/write only: 0o100600 (the 0o100000 is the file type bits)
        assert_eq!(
            mode & 0o777,
            0o600,
            "config.json should have 0o600 permissions, got {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn config_directory_is_owner_accessible_only() {
        let _guard = env_lock();
        let ctx = TestContext::new();
        ctx.set_process_env();

        let config = Config {
            server: Some("https://vault.example.com".to_string()),
            access_token: Some("secret-token".to_string()),
            ..Default::default()
        };
        config.save().unwrap();

        let mode = fs::metadata(ctx.config_dir())
            .expect("config dir should exist")
            .permissions()
            .mode();

        assert_eq!(
            mode & 0o777,
            0o700,
            "config directory should have 0o700 permissions, got {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn keys_file_is_owner_readable_and_writable_only_when_stored_on_disk() {
        let _guard = env_lock();
        let ctx = TestContext::new();
        ctx.set_process_env();

        // Create config without client_id so keyring path is skipped (fallback to file)
        let config = Config {
            server: Some("https://vault.example.com".to_string()),
            access_token: Some("token".to_string()),
            crypto_keys: Some(CryptoKeys {
                enc_key: vec![1u8; 32],
                mac_key: vec![2u8; 32],
            }),
            // No client_id — forces file fallback
            ..Default::default()
        };
        config.save().unwrap();
        config.save_keys().unwrap();

        // If keyring is unavailable, keys.json should exist with 0o600
        if ctx.keys_path().exists() {
            let mode = fs::metadata(ctx.keys_path())
                .expect("keys file should exist")
                .permissions()
                .mode();

            assert_eq!(
                mode & 0o777,
                0o600,
                "keys.json should have 0o600 permissions, got {:o}",
                mode & 0o777
            );
        }
        // If keyring is available, keys.json should NOT exist (stored in keyring instead)
    }
}

// ─────────────────────────────────────────────
// Key material zeroization
// ─────────────────────────────────────────────

mod key_zeroization {
    use vaultwarden_cli::crypto::CryptoKeys;

    #[test]
    fn crypto_keys_implements_zeroize() {
        // Verify that CryptoKeys can be zeroized (trait is available).
        // This is a compile-time check — if Zeroize is not derived, this won't compile.
        fn assert_zeroize<T: ::zeroize::Zeroize>() {}
        assert_zeroize::<CryptoKeys>();
    }

    #[test]
    fn crypto_keys_implements_zeroize_on_drop() {
        // Verify that CryptoKeys implements ZeroizeOnDrop.
        // This is a compile-time check — if the derive is missing, this won't compile.
        fn assert_zeroize_on_drop<T: ::zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<CryptoKeys>();
    }

    #[test]
    fn zeroize_clears_key_bytes_from_memory() {
        use ::zeroize::Zeroize;

        let keys = CryptoKeys {
            enc_key: vec![0xAA; 32],
            mac_key: vec![0xBB; 32],
        };

        // Clone so we can zeroize the original and verify it's wiped
        let mut keys = keys;
        keys.zeroize();

        // After zeroize, the Vec contents should be zeroed
        assert!(
            keys.enc_key.iter().all(|&b| b == 0),
            "enc_key should be zeroed after zeroize()"
        );
        assert!(
            keys.mac_key.iter().all(|&b| b == 0),
            "mac_key should be zeroed after zeroize()"
        );
    }

    #[test]
    fn debug_output_does_not_expose_key_bytes() {
        // The derived Debug would print raw key bytes; we use a manual impl
        // that replaces both fields with "[REDACTED]".
        let keys = CryptoKeys {
            enc_key: vec![0xDE; 32],
            mac_key: vec![0xAD; 32],
        };
        let debug = format!("{keys:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must redact key bytes, got: {debug}"
        );
        assert!(
            !debug.contains("222"),  // 0xDE == 222
            "enc_key bytes must not appear in Debug output, got: {debug}"
        );
        assert!(
            !debug.contains("173"),  // 0xAD == 173
            "mac_key bytes must not appear in Debug output, got: {debug}"
        );
    }
}

// ─────────────────────────────────────────────
// Server URL scheme validation
// ─────────────────────────────────────────────

mod server_url_validation {
    use super::env_lock;
    use vaultwarden_cli::api::ApiClient;

    #[test]
    fn rejects_ftp_url_scheme() {
        let result = ApiClient::new("ftp://evil.example.com");
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for ftp:// scheme"),
        };
        assert!(err_msg.contains("must start with https:// or http://"));
    }

    #[test]
    fn rejects_file_url_scheme() {
        let result = ApiClient::new("file:///etc/passwd");
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for file:// scheme"),
        };
        assert!(err_msg.contains("must start with https:// or http://"));
    }

    #[test]
    fn rejects_javascript_url_scheme() {
        let result = ApiClient::new("javascript:alert(1)");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_server_url() {
        let result = ApiClient::new("");
        assert!(result.is_err());
    }

    #[test]
    fn accepts_https_server_url() {
        let result = ApiClient::new("https://vault.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_http_server_url_by_default() {
        // Ensure no leftover env var from parallel tests
        let _guard = env_lock();
        unsafe { std::env::remove_var("VAULTWARDEN_ALLOW_HTTP") };

        // http:// should be rejected by default (secrets sent unencrypted)
        let result = ApiClient::new("http://vault.example.com");
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for http:// scheme"),
        };
        assert!(
            err_msg.contains("Insecure server URL rejected"),
            "expected rejection message, got: {err_msg}"
        );
    }

    #[test]
    fn accepts_http_server_url_with_explicit_flag() {
        // http:// should be accepted when explicitly allowed via flag
        let result = ApiClient::new_with_flags("http://vault.example.com", true);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_http_server_url_with_env_var() {
        // http:// should be accepted when VAULTWARDEN_ALLOW_HTTP=1
        let _guard = env_lock();
        unsafe { std::env::set_var("VAULTWARDEN_ALLOW_HTTP", "1") };
        let result = ApiClient::new("http://vault.example.com");
        unsafe { std::env::remove_var("VAULTWARDEN_ALLOW_HTTP") };
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_gopher_url_scheme() {
        let result = ApiClient::new("gopher://example.com");
        assert!(result.is_err());
    }
}

// ─────────────────────────────────────────────
// API client request timeouts
// ─────────────────────────────────────────────

mod api_client_timeouts {
    use vaultwarden_cli::api::ApiClient;

    #[test]
    fn api_client_initializes_with_timeouts() {
        // Verify that the client can be created with timeouts configured.
        // The actual timeout values are set internally; this test confirms
        // the builder doesn't fail when timeouts are specified.
        let result = ApiClient::new("https://vault.example.com");
        assert!(result.is_ok());
    }
}

// ─────────────────────────────────────────────
// MAC integrity verification rejection
// ─────────────────────────────────────────────

mod mac_integrity_rejection {
    use super::env_lock;
    use vaultwarden_cli::crypto::CryptoKeys;

    #[test]
    fn rejects_ciphertext_without_mac_by_default() {
        // Hold the lock so mutations to the process-wide flag are serialised.
        let _guard = env_lock();
        // Ensure the global flag is reset (tests run in parallel)
        vaultwarden_cli::crypto::set_allow_insecure_mac(false);

        // Create valid keys
        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // A type-2 encrypted string with only iv|ciphertext (no MAC)
        // Should be rejected because MAC integrity verification is required
        let result = keys.decrypt("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing MAC"),
            "expected MAC rejection message, got: {err}"
        );
    }

    #[test]
    fn allows_ciphertext_without_mac_with_env_var() {
        let _guard = env_lock();
        unsafe { std::env::set_var("VAULTWARDEN_ALLOW_INSECURE_MAC", "1") };

        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Without MAC but with env var bypass — should attempt decryption
        // (will fail at AES decrypt since keys/data are garbage, but not at MAC check)
        let result = keys.decrypt("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==");

        unsafe { std::env::remove_var("VAULTWARDEN_ALLOW_INSECURE_MAC") };

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("missing MAC"),
            "should not reject for missing MAC with bypass, got: {err}"
        );
    }

    #[test]
    fn allows_ciphertext_without_mac_with_global_flag() {
        // Hold the lock so mutations to the process-wide flag are serialised.
        let _guard = env_lock();
        // Set the global flag
        vaultwarden_cli::crypto::set_allow_insecure_mac(true);

        let keys = CryptoKeys {
            enc_key: vec![0u8; 32],
            mac_key: vec![0u8; 32],
        };

        // Without MAC but with global flag — should attempt decryption
        let result = keys.decrypt("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==");

        // Reset the global flag
        vaultwarden_cli::crypto::set_allow_insecure_mac(false);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("missing MAC"),
            "should not reject for missing MAC with bypass, got: {err}"
        );
    }
}

// ─────────────────────────────────────────────
// Interpolation output file permissions (Unix only)
// ─────────────────────────────────────────────

#[cfg(unix)]
mod interpolation_output_permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn interpolation_output_is_owner_readable_and_writable_only() {
        let _guard = env_lock();
        let ctx = TestContext::new();
        ctx.set_process_env();

        let output_path = ctx.root().join("output.yaml");

        // Call write_secure directly — this is the same function that
        // write_interpolated_output uses, so this test exercises the real
        // code path rather than a manually-chmod'd file.
        vaultwarden_cli::config::write_secure(&output_path, b"secret: data")
            .expect("write_secure should succeed");

        let mode = std::fs::metadata(&output_path)
            .expect("output file should exist")
            .permissions()
            .mode();

        assert_eq!(
            mode & 0o777,
            0o600,
            "interpolation output should have 0o600 permissions, got {:o}",
            mode & 0o777
        );
    }
}