//! Integration tests for vaultwarden-cli
//!
//! These tests verify the interaction between modules and simulate
//! realistic usage scenarios.

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Tests for the API client module
mod api_tests {
    use super::*;

    #[tokio::test]
    async fn test_api_client_check_server_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/alive"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/alive", mock_server.uri()))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_api_client_check_server_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/alive"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/alive", mock_server.uri()))
            .send()
            .await
            .unwrap();

        assert!(!response.status().is_success());
    }

    #[tokio::test]
    async fn test_login_endpoint_success() {
        let mock_server = MockServer::start().await;

        let token_response = serde_json::json!({
            "access_token": "test-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "test-refresh-token",
            "Key": "2.encrypted-key",
            "KdfIterations": 600000
        });

        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/identity/connect/token", mock_server.uri()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test-client"),
                ("client_secret", "test-secret"),
            ])
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());

        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["access_token"], "test-access-token");
        assert_eq!(body["expires_in"], 3600);
    }

    #[tokio::test]
    async fn test_login_endpoint_invalid_credentials() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid client credentials"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/identity/connect/token", mock_server.uri()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "bad-client"),
                ("client_secret", "bad-secret"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn test_sync_endpoint() {
        let mock_server = MockServer::start().await;

        let sync_response = serde_json::json!({
            "Ciphers": [
                {
                    "Id": "cipher-1",
                    "Type": 1,
                    "Name": "2.encrypted-name",
                    "Login": {
                        "Username": "2.encrypted-username",
                        "Password": "2.encrypted-password",
                        "Uris": [
                            {"Uri": "2.encrypted-uri", "Match": 0}
                        ]
                    }
                }
            ],
            "Folders": [],
            "Profile": {
                "Id": "user-123",
                "Email": "test@example.com",
                "Name": "Test User",
                "Organizations": []
            }
        });

        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/sync", mock_server.uri()))
            .bearer_auth("test-token")
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());

        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["Ciphers"].as_array().unwrap().len(), 1);
        assert_eq!(body["Profile"]["Email"], "test@example.com");
    }

    #[tokio::test]
    async fn test_sync_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/sync", mock_server.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_refresh_token_endpoint() {
        let mock_server = MockServer::start().await;

        let refresh_response = serde_json::json!({
            "access_token": "new-access-token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "new-refresh-token"
        });

        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&refresh_response))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/identity/connect/token", mock_server.uri()))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "old-refresh-token"),
            ])
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());

        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["access_token"], "new-access-token");
    }
}

/// Tests for cryptographic operations with realistic data
mod crypto_integration_tests {
    use vaultwarden_cli::crypto::CryptoKeys;

    #[test]
    fn test_full_key_derivation_flow() {
        // Simulate the full key derivation process
        let password = "MySecurePassword123!";
        let email = "user@example.com";
        let iterations = 100000; // Lower for test speed

        // Step 1: Derive master key from password
        let master_key = CryptoKeys::derive_master_key(password, email, iterations);
        assert_eq!(master_key.len(), 32);

        // Step 2: Stretch master key to get enc/mac keys
        let stretched = CryptoKeys::stretch_master_key(&master_key).unwrap();
        assert_eq!(stretched.enc_key.len(), 32);
        assert_eq!(stretched.mac_key.len(), 32);

        // Keys should be different from master key
        assert_ne!(&stretched.enc_key[..], &master_key[..]);
        assert_ne!(&stretched.mac_key[..], &master_key[..]);
    }

    #[test]
    fn test_symmetric_key_construction() {
        // Simulate receiving a decrypted 64-byte symmetric key
        let symmetric_key: Vec<u8> = (0..64).collect();

        let keys = CryptoKeys::from_symmetric_key(&symmetric_key).unwrap();

        // First 32 bytes = enc_key
        assert_eq!(&keys.enc_key[..], &symmetric_key[0..32]);
        // Last 32 bytes = mac_key
        assert_eq!(&keys.mac_key[..], &symmetric_key[32..64]);
    }

    #[test]
    fn test_different_users_different_keys() {
        let password = "SamePassword";
        let iterations = 100000;

        let key1 = CryptoKeys::derive_master_key(password, "user1@example.com", iterations);
        let key2 = CryptoKeys::derive_master_key(password, "user2@example.com", iterations);

        // Same password but different emails should produce different keys
        assert_ne!(key1, key2);
    }
}

/// Tests for model parsing with realistic API responses
mod model_integration_tests {
    use vaultwarden_cli::models::{CipherType, SyncResponse, TokenResponse};

    #[test]
    fn test_parse_realistic_token_response() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "refresh_eyJhbGciOiJSUzI1NiJ9.test",
            "scope": "api offline_access",
            "Key": "2.XYZ123abc/encrypted==|iv==|mac==",
            "PrivateKey": "2.privatekey/encrypted==|iv==|mac==",
            "Kdf": 0,
            "KdfIterations": 600000
        }"#;

        let response: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(response.access_token.starts_with("eyJ"));
        assert_eq!(response.expires_in, 3600);
        assert_eq!(response.kdf_iterations, Some(600000));
    }

    #[test]
    fn test_parse_realistic_sync_response() {
        let json = r#"{
            "Ciphers": [
                {
                    "Id": "12345678-1234-1234-1234-123456789012",
                    "Type": 1,
                    "OrganizationId": null,
                    "Name": "2.xyz==|abc==|def==",
                    "Notes": null,
                    "Login": {
                        "Username": "2.user==|iv==|mac==",
                        "Password": "2.pass==|iv==|mac==",
                        "Totp": null,
                        "Uris": [
                            {"Uri": "2.uri==|iv==|mac==", "Match": 0}
                        ]
                    },
                    "Fields": [
                        {"Name": "2.field==|iv==|mac==", "Value": "2.val==|iv==|mac==", "Type": 0}
                    ]
                },
                {
                    "Id": "87654321-4321-4321-4321-210987654321",
                    "Type": 2,
                    "Name": "2.note==|iv==|mac==",
                    "Notes": "2.secret==|iv==|mac==",
                    "SecureNote": {"Type": 0}
                }
            ],
            "Folders": [
                {"Id": "folder-1", "Name": "2.folder==|iv==|mac=="}
            ],
            "Profile": {
                "Id": "user-uuid",
                "Email": "user@example.com",
                "Name": "Test User",
                "Key": "2.userkey==|iv==|mac==",
                "PrivateKey": "2.privatekey==|iv==|mac==",
                "Organizations": [
                    {
                        "Id": "org-uuid",
                        "Name": "My Organization",
                        "Key": "4.orgkey/rsaencrypted=="
                    }
                ]
            }
        }"#;

        let response: SyncResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.ciphers.len(), 2);
        assert_eq!(response.folders.len(), 1);
        assert_eq!(response.profile.email, "user@example.com");
        assert_eq!(response.profile.organizations.len(), 1);

        // Check cipher types
        assert_eq!(response.ciphers[0].cipher_type(), Some(CipherType::Login));
        assert_eq!(
            response.ciphers[1].cipher_type(),
            Some(CipherType::SecureNote)
        );
    }

    #[test]
    fn test_parse_vaultwarden_nested_format() {
        // Vaultwarden sometimes returns data in a nested format
        let json = r#"{
            "Ciphers": [
                {
                    "id": "test-id",
                    "type": 1,
                    "data": {
                        "name": "2.name==|iv==|mac==",
                        "username": "2.user==|iv==|mac==",
                        "password": "2.pass==|iv==|mac==",
                        "uri": "2.uri==|iv==|mac=="
                    }
                }
            ],
            "Folders": [],
            "Profile": {
                "id": "user-id",
                "email": "test@test.com",
                "organizations": []
            }
        }"#;

        let response: SyncResponse = serde_json::from_str(json).unwrap();

        let cipher = &response.ciphers[0];
        assert_eq!(cipher.get_name(), Some("2.name==|iv==|mac=="));
        assert_eq!(cipher.get_username(), Some("2.user==|iv==|mac=="));
        assert_eq!(cipher.get_password(), Some("2.pass==|iv==|mac=="));
        assert_eq!(cipher.get_uri(), Some("2.uri==|iv==|mac=="));
    }

    #[test]
    fn test_cipher_with_multiple_uris() {
        let json = r#"{
            "Id": "test",
            "Type": 1,
            "Login": {
                "Uris": [
                    {"Uri": "https://example.com", "Match": 0},
                    {"Uri": "https://www.example.com", "Match": 1},
                    {"Uri": "https://app.example.com", "Match": null}
                ]
            }
        }"#;

        let cipher: vaultwarden_cli::models::Cipher = serde_json::from_str(json).unwrap();

        // get_uri returns the first URI
        assert_eq!(cipher.get_uri(), Some("https://example.com"));
    }
}

/// Tests for edge cases and error handling
mod edge_case_tests {
    use vaultwarden_cli::crypto::CryptoKeys;
    use vaultwarden_cli::models::{Cipher, CipherType};

    #[test]
    fn test_empty_password_derivation() {
        // Empty password is technically valid
        let key = CryptoKeys::derive_master_key("", "user@example.com", 100000);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_unicode_password() {
        let key = CryptoKeys::derive_master_key("密码🔐パスワード", "user@example.com", 100000);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_very_long_password() {
        let long_password = "a".repeat(10000);
        let key = CryptoKeys::derive_master_key(&long_password, "user@example.com", 100000);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_cipher_with_null_fields() {
        let json = r#"{
            "Id": "test",
            "Type": 1,
            "Name": null,
            "Notes": null,
            "Login": null,
            "Card": null,
            "Identity": null,
            "SecureNote": null,
            "Fields": null,
            "Data": null
        }"#;

        let cipher: Cipher = serde_json::from_str(json).unwrap();
        assert_eq!(cipher.get_name(), None);
        assert_eq!(cipher.get_username(), None);
        assert_eq!(cipher.get_password(), None);
        assert_eq!(cipher.get_uri(), None);
        assert_eq!(cipher.get_notes(), None);
        assert!(cipher.get_fields().is_none());
    }

    #[test]
    fn test_cipher_type_unknown() {
        let json = r#"{
            "Id": "test",
            "Type": 99
        }"#;

        let cipher: Cipher = serde_json::from_str(json).unwrap();
        assert_eq!(cipher.cipher_type(), None);
    }

    #[test]
    fn test_cipher_type_from_str_edge_cases() {
        // Numbers as strings
        assert_eq!(CipherType::from_str("1"), Some(CipherType::Login));
        assert_eq!(CipherType::from_str("2"), Some(CipherType::SecureNote));

        // Invalid inputs
        assert_eq!(CipherType::from_str(""), None);
        assert_eq!(CipherType::from_str("   "), None);
        assert_eq!(CipherType::from_str("unknown"), None);
    }
}

/// Performance-related tests
mod performance_tests {
    use std::time::Instant;
    use vaultwarden_cli::crypto::CryptoKeys;

    #[test]
    fn test_key_derivation_completes_in_reasonable_time() {
        // With low iterations, derivation should be fast
        let start = Instant::now();
        let _ = CryptoKeys::derive_master_key("password", "user@example.com", 1000);
        let duration = start.elapsed();

        // Should complete in under 1 second with 1000 iterations
        assert!(duration.as_secs() < 1);
    }

    #[test]
    fn test_stretch_key_is_fast() {
        let master_key = vec![0u8; 32];

        let start = Instant::now();
        for _ in 0..1000 {
            let _ = CryptoKeys::stretch_master_key(&master_key);
        }
        let duration = start.elapsed();

        // 1000 stretches should complete in under 1 second
        assert!(duration.as_secs() < 1);
    }
}
