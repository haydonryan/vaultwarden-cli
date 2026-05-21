//! Live tests: `run` and `run-uri` — env injection, env_clear isolation, info flag.
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use crate::live_env::{
    FIXTURE_LOGIN_FIELD_API_KEY_VALUE, FIXTURE_LOGIN_NAME, FIXTURE_LOGIN_PASSWORD,
    FIXTURE_LOGIN_USERNAME, FIXTURE_LOGIN2_NAME, FIXTURE_LOGIN2_PASSWORD, FIXTURE_LOGIN2_USERNAME,
    LiveTestEnv,
};
use predicates::prelude::*;

// ── helper: env-var prefix from item name ─────────────────────────────────
//
// sanitize_env_name: uppercase + non-alphanum → '_'
// "Live-Test-Login"  → "LIVE_TEST_LOGIN"

const LIVE_TEST_LOGIN_PREFIX: &str = "LIVE_TEST_LOGIN";
const LIVE_TEST_LOGIN2_PREFIX: &str = "LIVE_TEST_LOGIN_2";

// ── run single item by positional name ────────────────────────────────────

#[tokio::test]
async fn run_injects_vault_vars_into_child_env() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // Ask `env` to print its environment; vault vars should be present.
    let output = env
        .binary()
        .args(["run", FIXTURE_LOGIN_NAME, "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN_PREFIX}_USERNAME={FIXTURE_LOGIN_USERNAME}"
        )),
        "USERNAME not injected: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN_PREFIX}_PASSWORD={FIXTURE_LOGIN_PASSWORD}"
        )),
        "PASSWORD not injected: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN_PREFIX}_API_KEY={FIXTURE_LOGIN_FIELD_API_KEY_VALUE}"
        )),
        "API_KEY custom field not injected: {stdout}"
    );
}

// ── --name flag ───────────────────────────────────────────────────────────

#[tokio::test]
async fn run_with_name_flag() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["run", "--name", FIXTURE_LOGIN_NAME, "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!(
        "{LIVE_TEST_LOGIN_PREFIX}_PASSWORD={FIXTURE_LOGIN_PASSWORD}"
    )));
}

// ── comma-separated names ─────────────────────────────────────────────────

#[tokio::test]
async fn run_comma_separated_names_injects_all() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let names = format!("{FIXTURE_LOGIN_NAME},{FIXTURE_LOGIN2_NAME}");
    let output = env
        .binary()
        .args(["run", &names, "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Both items must appear.
    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN_PREFIX}_PASSWORD={FIXTURE_LOGIN_PASSWORD}"
        )),
        "first item not injected: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN2_PREFIX}_PASSWORD={FIXTURE_LOGIN2_PASSWORD}"
        )),
        "second item not injected: {stdout}"
    );
}

// ── --info flag ───────────────────────────────────────────────────────────

#[tokio::test]
async fn run_info_flag_shows_item_names() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // --info should print which item(s) are being loaded, then run child.
    let output = env
        .binary()
        .args(["run", "--info", FIXTURE_LOGIN_NAME, "--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // --info prints env var names (e.g. LIVE_TEST_LOGIN_PASSWORD) to stdout.
    let env_prefix: String = FIXTURE_LOGIN_NAME
        .to_uppercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    assert!(
        stdout.contains(&env_prefix),
        "--info should print env var names to stdout: {stdout}"
    );
}

// ── env_clear isolation ───────────────────────────────────────────────────

#[tokio::test]
async fn run_does_not_leak_parent_env_to_child() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // Set a sentinel var that must NOT reach the child process.
    let output = env
        .binary()
        .env("VAULTWARDEN_PARENT_SENTINEL", "should-not-leak")
        .args(["run", FIXTURE_LOGIN_NAME, "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("VAULTWARDEN_PARENT_SENTINEL"),
        "parent sentinel var leaked into child env: {stdout}"
    );
}

#[tokio::test]
async fn run_child_receives_whitelisted_vars() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["run", FIXTURE_LOGIN_NAME, "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // PATH must always be present (whitelisted).
    assert!(stdout.contains("PATH="), "PATH not in child env: {stdout}");
}

// ── item not found ────────────────────────────────────────────────────────

#[tokio::test]
async fn run_with_unknown_item_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["run", "zzz-no-such-item-zzz", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(not found|no item)").unwrap());
}

// ── child exit code propagated ────────────────────────────────────────────

#[tokio::test]
async fn run_propagates_child_exit_code() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // `false` always exits with code 1.
    let output = env
        .binary()
        .args(["run", FIXTURE_LOGIN_NAME, "--", "false"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "expected non-zero exit when child fails"
    );
}

// ── run-uri ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn run_uri_injects_vars_for_matching_item() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["run-uri", "live-test.example.com", "--", "env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(&format!(
            "{LIVE_TEST_LOGIN_PREFIX}_PASSWORD={FIXTURE_LOGIN_PASSWORD}"
        )),
        "URI-matched item not injected: {stdout}"
    );
}

#[tokio::test]
async fn run_uri_no_match_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    env.binary()
        .args(["run-uri", "zzz-no-matching-uri.invalid", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(not found|no item)").unwrap());
}

#[tokio::test]
async fn run_uri_info_flag_reports_matched_item() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let output = env
        .binary()
        .args(["run-uri", "--info", "live-test.example.com", "--", "true"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // --info prints env var names (e.g. LIVE_TEST_LOGIN_PASSWORD) to stdout.
    let env_prefix: String = FIXTURE_LOGIN_NAME
        .to_uppercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    assert!(
        stdout.contains(&env_prefix),
        "--info should name the matched item via env vars to stdout: {stdout}"
    );
}

// ── run requires unlock ───────────────────────────────────────────────────

#[tokio::test]
async fn run_requires_vault_unlocked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    env.binary()
        .args(["run", FIXTURE_LOGIN_NAME, "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(lock|unlock|key)").unwrap());
}
