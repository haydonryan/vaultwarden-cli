//! Live tests: `get` and `get-uri` — all output formats, scopes, and error paths.
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use crate::live_env::{
    FIXTURE_LOGIN_FIELD_API_KEY_NAME, FIXTURE_LOGIN_FIELD_API_KEY_VALUE, FIXTURE_LOGIN_NAME,
    FIXTURE_LOGIN_PASSWORD, FIXTURE_LOGIN_URI, FIXTURE_LOGIN_USERNAME, FIXTURE_SSH_NAME,
    FIXTURE_SSH_PUBLIC_KEY, LiveTestEnv,
};
use predicates::prelude::*;

// ── get by name ───────────────────────────────────────────────────────────

#[tokio::test]
async fn get_by_exact_name_json() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME])
        .output()
        .unwrap();
    assert!(output.status.success(), "expected success");

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("get default output should be JSON");
    assert_eq!(json["name"].as_str().unwrap_or(""), FIXTURE_LOGIN_NAME);
    assert_eq!(
        json["username"].as_str().unwrap_or(""),
        FIXTURE_LOGIN_USERNAME
    );
    assert_eq!(
        json["password"].as_str().unwrap_or(""),
        FIXTURE_LOGIN_PASSWORD
    );
}

#[tokio::test]
async fn get_by_item_id() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", &env.login_item_id])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap_or(""), FIXTURE_LOGIN_NAME);
}

#[tokio::test]
async fn get_not_found_returns_error() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["get", "zzz-no-such-item-zzz"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

// ── output formats ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_format_json_contains_all_fields() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["id"].is_string());
    assert!(json["name"].is_string());
    assert!(json["username"].is_string());
    assert!(json["password"].is_string());
    assert!(json["fields"].is_array());
}

#[tokio::test]
async fn get_format_env_produces_key_value_pairs() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--format", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Env format should have LIVE_TEST_LOGIN_USERNAME=...
    assert!(
        stdout.contains("LIVE_TEST_LOGIN_USERNAME"),
        "missing USERNAME var: {stdout}"
    );
    assert!(
        stdout.contains("LIVE_TEST_LOGIN_PASSWORD"),
        "missing PASSWORD var: {stdout}"
    );
    // Custom field api_key
    assert!(
        stdout.contains("LIVE_TEST_LOGIN_API_KEY"),
        "missing custom field API_KEY var: {stdout}"
    );
}

#[tokio::test]
async fn get_format_value_outputs_only_password() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--format", "value"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        FIXTURE_LOGIN_PASSWORD,
        "format=value should output only the password"
    );
}

#[tokio::test]
async fn get_format_username_outputs_only_username() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--format", "username"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        FIXTURE_LOGIN_USERNAME,
        "format=username should output only the username"
    );
}

#[tokio::test]
async fn get_shorthand_password_flag() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--password"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        FIXTURE_LOGIN_PASSWORD
    );
}

#[tokio::test]
async fn get_shorthand_username_flag() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--username"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        FIXTURE_LOGIN_USERNAME
    );
}

// ── custom fields ─────────────────────────────────────────────────────────

#[tokio::test]
async fn get_json_includes_custom_fields() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_LOGIN_NAME, "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let fields = json["fields"].as_array().expect("fields array");
    let api_key_field = fields
        .iter()
        .find(|f| f["name"].as_str().unwrap_or("") == FIXTURE_LOGIN_FIELD_API_KEY_NAME)
        .expect("api_key field not found");
    assert_eq!(
        api_key_field["value"].as_str().unwrap_or(""),
        FIXTURE_LOGIN_FIELD_API_KEY_VALUE
    );
}

// ── SSH key item ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_ssh_item_includes_key_fields_in_json() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get", FIXTURE_SSH_NAME, "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Public key should be present.
    let pub_key = json["ssh_public_key"].as_str().unwrap_or("");
    assert!(
        !pub_key.is_empty(),
        "ssh_public_key missing from SSH item JSON"
    );
    assert!(
        pub_key.contains("ssh-ed25519") || pub_key.contains("live-test"),
        "unexpected public key value: {pub_key}"
    );
}

// ── get-uri ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_uri_by_exact_domain() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // "live-test.example.com" is part of FIXTURE_LOGIN_URI.
    let output = env
        .binary()
        .args(["get-uri", "live-test.example.com"])
        .output()
        .unwrap();
    assert!(output.status.success(), "expected success");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap_or(""), FIXTURE_LOGIN_NAME);
}

#[tokio::test]
async fn get_uri_with_format_value() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["get-uri", "live-test.example.com", "--format", "value"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        FIXTURE_LOGIN_PASSWORD
    );
}

#[tokio::test]
async fn get_uri_no_match_returns_error() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["get-uri", "zzz-no-matching-uri-zzz.invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(not found|no item)").unwrap());
}

#[tokio::test]
async fn get_uri_partial_uri_matches() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // Just the path portion should still match via contains().
    let output = env
        .binary()
        .args(["get-uri", "example.com/login"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["name"].as_str().unwrap_or(""), FIXTURE_LOGIN_NAME);
}

// ── get when not logged in ────────────────────────────────────────────────

#[tokio::test]
async fn get_requires_login() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    env.binary()
        .args(["get", FIXTURE_LOGIN_NAME])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(login|not logged in)").unwrap());
}
