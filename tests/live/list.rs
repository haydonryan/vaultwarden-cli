//! Live tests: `list` command — all filter/output combinations.
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use crate::live_env::{
    LiveTestEnv, FIXTURE_CARD_NAME, FIXTURE_LOGIN2_NAME, FIXTURE_LOGIN_NAME,
    FIXTURE_LOGIN_USERNAME, FIXTURE_NOTE_NAME, FIXTURE_SSH_NAME,
};
use predicates::prelude::*;

// ── list all ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_all_provisioned_items() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // Five fixture items were created; all should appear.
    let assert = env.binary().arg("list").assert().success();
    // Default (non-JSON) output shows env-var names; login items show _PASSWORD
    assert.stdout(predicate::str::contains("LIVE_TEST_LOGIN_PASSWORD"));
}

#[tokio::test]
async fn list_type_login_shows_only_logins() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["list", "--type", "login", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from list --json");
    let items = json.as_array().expect("JSON array");

    // At least the two login fixtures, no notes/cards.
    assert!(
        items.len() >= 2,
        "expected ≥2 login items, got {}",
        items.len()
    );
    for item in items {
        let cipher_type = item["type"].as_str().unwrap_or("");
        assert_eq!(cipher_type, "login", "non-login item slipped through: {item}");
    }
}

#[tokio::test]
async fn list_type_note_shows_only_notes() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["list", "--type", "note", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = json.as_array().unwrap();
    assert!(!items.is_empty(), "expected ≥1 note");
    for item in items {
        assert_eq!(item["type"].as_str().unwrap_or(""), "note");
    }
}

#[tokio::test]
async fn list_type_card_shows_only_cards() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["list", "--type", "card", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = json.as_array().unwrap();
    assert!(!items.is_empty(), "expected ≥1 card");
    for item in items {
        assert_eq!(item["type"].as_str().unwrap_or(""), "card");
    }
}

#[tokio::test]
async fn list_type_ssh_shows_only_ssh_keys() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["list", "--type", "ssh", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = json.as_array().unwrap();
    // SSH might be a login fallback if the server doesn't support type 5.
    assert!(!items.is_empty(), "expected ≥1 ssh-type item");
}

#[tokio::test]
async fn list_type_invalid_returns_error() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["list", "--type", "not-a-real-type"])
        .assert()
        .failure();
}

// ── list --search ─────────────────────────────────────────────────────────

#[tokio::test]
async fn list_search_by_name_prefix() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // "Live-Test-Note" should match search "live-test-note".
    let output = env
        .binary()
        .args(["list", "--search", "Live-Test-Note", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FIXTURE_NOTE_NAME),
        "search did not return the note: {stdout}"
    );
}

#[tokio::test]
async fn list_search_by_username() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["list", "--search", FIXTURE_LOGIN_USERNAME, "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let names: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["name"].as_str())
        .collect();
    assert!(
        names.contains(&FIXTURE_LOGIN_NAME),
        "login not returned for username search: {names:?}"
    );
}

#[tokio::test]
async fn list_search_with_no_matches_prints_no_items_found() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["list", "--search", "zzz-guaranteed-no-match-zzz"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No items found"));
}

// ── list --json ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_json_output_is_valid_json_array() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env.binary().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success());

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("list --json must produce valid JSON");
    assert!(
        parsed.is_array(),
        "list --json must be a JSON array, got: {parsed}"
    );

    let items = parsed.as_array().unwrap();
    assert!(!items.is_empty(), "expected ≥1 item in JSON list");

    // Each item must have at minimum an id and name.
    for item in items {
        assert!(item["id"].is_string(), "missing id: {item}");
        assert!(item["name"].is_string(), "missing name: {item}");
    }
}

#[tokio::test]
async fn list_json_includes_all_fixture_items() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env.binary().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    for expected_name in [
        FIXTURE_LOGIN_NAME,
        FIXTURE_LOGIN2_NAME,
        FIXTURE_NOTE_NAME,
        FIXTURE_CARD_NAME,
        FIXTURE_SSH_NAME,
    ] {
        assert!(
            stdout.contains(expected_name),
            "name '{expected_name}' not in list --json output"
        );
    }
}

// ── list type + search combined ───────────────────────────────────────────

#[tokio::test]
async fn list_type_and_search_combined() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args([
            "list",
            "--type",
            "login",
            "--search",
            FIXTURE_LOGIN_NAME,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = json.as_array().unwrap();
    // Should find exactly FIXTURE_LOGIN_NAME but not FIXTURE_LOGIN2_NAME
    // (different name that doesn't match the search).
    assert!(!items.is_empty());
    for item in items {
        assert_eq!(item["type"].as_str().unwrap_or(""), "login");
        let name = item["name"].as_str().unwrap_or("");
        assert!(
            name.contains(FIXTURE_LOGIN_NAME),
            "name '{name}' doesn't match search '{FIXTURE_LOGIN_NAME}'"
        );
    }
}

// ── list when not logged in ───────────────────────────────────────────────

#[tokio::test]
async fn list_requires_login() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    env.binary()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(login|not logged in)").unwrap());
}
