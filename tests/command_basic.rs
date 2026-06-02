#![allow(clippy::pedantic, clippy::nursery)]

mod support;

use assert_cmd::Command;
use predicates::prelude::*;
use support::{
    TestContext, allow_insecure_key_file_fallback, encrypt_string_for_test, encrypted_user_key,
    env_lock, test_crypto_keys,
};
use vaultwarden_cli::config::Config;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn status_reports_logged_out_when_no_config_exists() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Not logged in"));
}

#[test]
fn logout_is_a_no_op_when_not_logged_in() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("logout")
        .assert()
        .success()
        .stdout(predicate::str::contains("Not currently logged in."));
}

#[test]
fn run_requires_a_selector_when_not_searching_by_uri() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "At least one of --name, --org, --folder, or --collection must be specified.",
        ));
}

#[test]
fn status_reports_logged_in_locked_details_from_saved_config() {
    let ctx = TestContext::new();
    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        client_id: Some("client-id".to_string()),
        email: Some("user@example.com".to_string()),
        access_token: Some("token".to_string()),
        token_expiry: Some(1),
        ..Default::default()
    })
    .unwrap();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains(
            "Server: https://vault.example.com",
        ))
        .stdout(predicate::str::contains("Client ID: client-id"))
        .stdout(predicate::str::contains("Email: user@example.com"))
        .stdout(predicate::str::contains("Token: Expired"))
        .stdout(predicate::str::contains("Vault: Locked"));
}

#[test]
fn status_reports_unlocked_when_saved_keys_exist() {
    let ctx = TestContext::new();
    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        access_token: Some("token".to_string()),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&test_crypto_keys()).unwrap();

    ctx.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains("Vault: Unlocked"));
}

#[test]
fn unlock_reads_password_from_environment() {
    let ctx = TestContext::new();
    let email = "user@example.com";
    let password = "MySecurePassword123!"; // secrets-ignore: test fixture
    let keys = test_crypto_keys();

    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        email: Some(email.to_string()),
        access_token: Some("token".to_string()),
        token_expiry: Some(i64::MAX),
        encrypted_key: Some(encrypted_user_key(password, email, 600000, &keys)),
        kdf_iterations: Some(600000),
        ..Default::default()
    })
    .unwrap();

    ctx.binary()
        .arg("unlock")
        .env("VAULTWARDEN_PASSWORD", password)
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked successfully!"));

    let _guard = env_lock();
    let _allow_key_file = allow_insecure_key_file_fallback();
    let saved = ctx.load_config().unwrap();
    let saved_keys = saved.crypto_keys.expect("saved user keys");
    assert_eq!(saved_keys.enc_key, keys.enc_key);
    assert_eq!(saved_keys.mac_key, keys.mac_key);
}

#[test]
fn unlock_fails_when_keys_cannot_be_persisted() {
    let ctx = TestContext::new();
    let email = "user@example.com";
    let password = "MySecurePassword123!"; // secrets-ignore: test fixture
    let keys = test_crypto_keys();

    ctx.write_config(&Config {
        server: Some("https://vault.example.com".to_string()),
        email: Some(email.to_string()),
        access_token: Some("token".to_string()),
        token_expiry: Some(i64::MAX),
        encrypted_key: Some(encrypted_user_key(password, email, 600000, &keys)),
        kdf_iterations: Some(600000),
        ..Default::default()
    })
    .unwrap();

    let mut cmd = Command::cargo_bin("vaultwarden-cli").unwrap();
    cmd.env("HOME", ctx.home_dir())
        .env("XDG_CONFIG_HOME", ctx.config_root())
        .env("VAULTWARDEN_PASSWORD", password)
        .env_remove("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE")
        .arg("unlock")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Vault unlocked successfully!").not())
        .stderr(predicate::str::contains("Vault keys were not persisted"));

    let saved = ctx.load_config().unwrap();
    assert!(
        saved.crypto_keys.is_none(),
        "unlock must not leave reusable saved keys when persistence failed"
    );
    assert!(
        !ctx.keys_path().exists(),
        "keys.json should not be written without explicit fallback"
    );
}

#[tokio::test]
async fn run_with_collection_scope_injects_all_matching_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [],
        "Folders": [],
        "Collections": [
            {
                "Id": "DZ1",
                "Name": "ignored-for-id-match",
                "OrganizationId": "org-1"
            }
        ],
        "Profile": {
            "Id": "user-1",
            "Email": "user@example.com",
            "Organizations": []
        }
    });

    let ciphers_response = serde_json::json!({
        "object": "list",
        "data": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": ["DZ1"]
            },
            {
                "Id": "cipher-2",
                "Type": 1,
                "Name": encrypt_string_for_test("Beta", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys),
                    "Password": encrypt_string_for_test("beta-secret", &keys)
                },
                "CollectionIds": ["DZ1"]
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(header("authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/ciphers"))
        .and(query_param("collectionId", "DZ1"))
        .and(header("authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ciphers_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("--collection")
        .arg("DZ1")
        .arg("--info")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_USERNAME"))
        .stdout(predicate::str::contains("ALPHA_PASSWORD"))
        .stdout(predicate::str::contains("BETA_USERNAME"))
        .stdout(predicate::str::contains("BETA_PASSWORD"));
}

#[tokio::test]
async fn run_with_multiple_name_flags_injects_multiple_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
            },
            {
                "Id": "cipher-2",
                "Type": 1,
                "Name": encrypt_string_for_test("Beta", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys),
                    "Password": encrypt_string_for_test("beta-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("--name")
        .arg("Alpha")
        .arg("--name")
        .arg("Beta")
        .arg("--info")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_USERNAME"))
        .stdout(predicate::str::contains("ALPHA_PASSWORD"))
        .stdout(predicate::str::contains("BETA_USERNAME"))
        .stdout(predicate::str::contains("BETA_PASSWORD"));
}

#[tokio::test]
async fn run_with_implicit_name_injects_matching_item() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("Alpha")
        .arg("--info")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_USERNAME"))
        .stdout(predicate::str::contains("ALPHA_PASSWORD"));
}

#[tokio::test]
async fn run_injects_env_vars_into_child_process() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("Alpha")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf '%s\\n%s\\n' \"$ALPHA_USERNAME\" \"$ALPHA_PASSWORD\"")
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("alpha-secret"));
}

#[tokio::test]
async fn run_injects_portable_env_vars_for_edge_case_item_names() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("123 café !!!", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("edge-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("123 café !!!")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf '%s\\n%s\\n' \"$ITEM_123_CAF_USERNAME\" \"$ITEM_123_CAF_PASSWORD\"")
        .assert()
        .success()
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("edge-secret"));
}

#[tokio::test]
async fn run_with_multiple_implicit_names_injects_multiple_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
            },
            {
                "Id": "cipher-2",
                "Type": 1,
                "Name": encrypt_string_for_test("Beta", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys),
                    "Password": encrypt_string_for_test("beta-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("Alpha")
        .arg("Beta")
        .arg("--info")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_USERNAME"))
        .stdout(predicate::str::contains("ALPHA_PASSWORD"))
        .stdout(predicate::str::contains("BETA_USERNAME"))
        .stdout(predicate::str::contains("BETA_PASSWORD"));
}

#[tokio::test]
async fn run_with_comma_separated_implicit_names_injects_multiple_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
            },
            {
                "Id": "cipher-2",
                "Type": 1,
                "Name": encrypt_string_for_test("Beta", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys),
                    "Password": encrypt_string_for_test("beta-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("run")
        .arg("Alpha,Beta")
        .arg("--info")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_USERNAME"))
        .stdout(predicate::str::contains("ALPHA_PASSWORD"))
        .stdout(predicate::str::contains("BETA_USERNAME"))
        .stdout(predicate::str::contains("BETA_PASSWORD"));
}

#[tokio::test]
async fn interpolate_skip_missing_reports_unmatched_placeholders_on_stderr() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;
    let input_path = ctx.root().join("config.yml");

    std::fs::write(
        &input_path,
        "username: ((Alpha.username))\npassword: ((Missing.password))\n",
    )
    .unwrap();

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
                },
                "CollectionIds": []
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("interpolate")
        .arg("--file")
        .arg(&input_path)
        .arg("--skip-missing")
        .assert()
        .success()
        .stdout(predicate::str::contains("username: alice"))
        .stdout(predicate::str::contains("password: ((Missing.password))"))
        .stderr(predicate::str::contains(
            "Unmatched placeholders left unchanged:",
        ))
        .stderr(predicate::str::contains("((Missing.password))"));
}

#[tokio::test]
async fn list_with_type_filter_shows_only_matching_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
                }
            },
            {
                "Id": "cipher-2",
                "Type": 2,
                "Name": encrypt_string_for_test("Beta Note", &keys),
                "SecureNote": { "Type": 0 }
            },
            {
                "Id": "cipher-3",
                "Type": 1,
                "Name": encrypt_string_for_test("Gamma Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys)
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--type")
        .arg("login")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_LOGIN_USERNAME"))
        .stdout(predicate::str::contains("GAMMA_LOGIN_USERNAME"))
        .stdout(predicate::str::contains("BETA_NOTE_USERNAME").not());
}

#[tokio::test]
async fn list_with_search_filter_matches_decrypted_data() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
                }
            },
            {
                "Id": "cipher-2",
                "Type": 1,
                "Name": encrypt_string_for_test("Beta Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("bob", &keys)
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--search")
        .arg("alice")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_LOGIN_USERNAME"))
        .stdout(predicate::str::contains("BETA_LOGIN_USERNAME").not());
}

#[tokio::test]
async fn list_with_no_filters_shows_all_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
                }
            },
            {
                "Id": "cipher-2",
                "Type": 2,
                "Name": encrypt_string_for_test("Beta Note", &keys),
                "SecureNote": { "Type": 0 }
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("ALPHA_LOGIN_USERNAME"))
        .stdout(predicate::str::contains("BETA_NOTE").not());
}

#[tokio::test]
async fn list_with_json_flag_includes_complete_items() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
                }
            },
            {
                "Id": "cipher-2",
                "Type": 2,
                "Name": encrypt_string_for_test("Beta Note", &keys),
                "SecureNote": { "Type": 0 }
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("["))
        .stdout(predicate::str::contains("\"name\": \"Alpha Login\""))
        .stdout(predicate::str::contains("\"name\": \"Beta Note\""));
}

#[tokio::test]
async fn list_json_requires_opt_in_when_stdout_is_captured() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-1",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys),
                    "Password": encrypt_string_for_test("alpha-secret", &keys)
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(2)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .env_remove("VAULTWARDEN_ALLOW_PLAINTEXT_JSON")
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--json")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Plaintext JSON output"))
        .stderr(predicate::str::contains("--allow-plaintext-json"));

    ctx.binary()
        .env_remove("VAULTWARDEN_ALLOW_PLAINTEXT_JSON")
        .arg("--allow-insecure-http")
        .arg("--allow-plaintext-json")
        .arg("list")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"password\": \"alpha-secret\""));
}

#[tokio::test]
async fn list_with_type_filter_uses_sync_ciphers_without_secondary_fetch() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-login",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
                }
            },
            {
                "Id": "cipher-ssh",
                "Type": 5,
                "Name": encrypt_string_for_test("Deploy Key", &keys),
                "SshKey": {
                    "PrivateKey": encrypt_string_for_test("PRIVATE-KEY", &keys),
                    "PublicKey": encrypt_string_for_test("PUBLIC-KEY", &keys)
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/ciphers"))
        .and(header("authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--type")
        .arg("ssh")
        .assert()
        .success()
        .stdout(predicate::str::contains("DEPLOY_KEY_SSH_PUBLIC_KEY"))
        .stdout(predicate::str::contains("DEPLOY_KEY_SSH_PRIVATE_KEY"))
        .stdout(predicate::str::contains("ALPHA_LOGIN_USERNAME").not())
        .stdout(predicate::str::contains("No items found.").not());
}

#[tokio::test]
async fn list_uses_sync_ciphers_without_ciphers_endpoint_fallback() {
    let ctx = TestContext::new();
    let keys = test_crypto_keys();
    let mock_server = MockServer::start().await;

    let sync_response = serde_json::json!({
        "Ciphers": [
            {
                "Id": "cipher-login",
                "Type": 1,
                "Name": encrypt_string_for_test("Alpha Login", &keys),
                "Login": {
                    "Username": encrypt_string_for_test("alice", &keys)
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
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    ctx.write_config(&Config {
        server: Some(mock_server.uri()),
        access_token: Some("access-token".to_string()),
        token_expiry: Some(i64::MAX),
        ..Default::default()
    })
    .unwrap();
    ctx.write_saved_user_keys(&keys).unwrap();

    ctx.binary()
        .arg("--allow-insecure-http")
        .arg("list")
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Alpha Login\""))
        .stderr(predicate::str::contains("Could not load /api/ciphers").not());
}
