//! Live tests: login, logout, lock, unlock, status.
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use crate::live_env::{FIXTURE_LOGIN_NAME, LiveTestEnv, TEST_PASSWORD};
use predicates::prelude::*;

// ── status ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_when_not_logged_in() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    env.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Not logged in"));
}

#[tokio::test]
async fn status_when_logged_in_locked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    // Remove keys so vault is locked.
    env.lock_vault();

    env.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains(&env.email))
        .stdout(predicate::str::contains("Vault: Locked"));
}

#[tokio::test]
async fn status_when_logged_in_unlocked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    // keys.json is written during provisioning → vault is unlocked.

    env.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"))
        .stdout(predicate::str::contains("Vault: Unlocked"));
}

// ── login ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_with_valid_credentials() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    // Start from a clean slate — no existing config.
    env.clear_session();

    env.binary()
        .args([
            "--allow-insecure-http",
            "login",
            "--server",
            &env.server_url,
            "--client-id",
            &env.client_id,
            "--client-secret",
            &env.client_secret,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Login successful!"));
}

#[tokio::test]
async fn login_with_invalid_client_secret_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    env.binary()
        .args([
            "--allow-insecure-http",
            "login",
            "--server",
            &env.server_url,
            "--client-id",
            &env.client_id,
            "--client-secret",
            "wrong-secret",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(login|auth|401|failed)").unwrap());
}

#[tokio::test]
async fn login_with_unreachable_server_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    env.binary()
        .args([
            "--allow-insecure-http",
            "login",
            "--server",
            "http://127.0.0.1:19", // no server listening here
            "--client-id",
            &env.client_id,
            "--client-secret",
            &env.client_secret,
        ])
        .assert()
        .failure();
}

#[tokio::test]
async fn login_does_not_store_access_token_in_config_json() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    // Run login.
    env.binary()
        .args([
            "--allow-insecure-http",
            "login",
            "--server",
            &env.server_url,
            "--client-id",
            &env.client_id,
            "--client-secret",
            &env.client_secret,
        ])
        .assert()
        .success();

    // config.json must not contain the access_token.
    let config_json =
        std::fs::read_to_string(env.config_dir.join("config.json")).expect("config.json");
    assert!(
        !config_json.contains("access_token"),
        "access_token found in config.json — it must be stored in tokens.json instead"
    );
}

// ── logout ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_clears_session() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // Confirm we start logged-in.
    env.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: Logged in"));

    // Log out.
    env.binary()
        .arg("logout")
        .assert()
        .success()
        .stdout(predicate::str::contains("Logged out"));

    // Now status says logged out.
    env.binary()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("Not logged in"));
}

#[tokio::test]
async fn logout_when_not_logged_in_is_graceful() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.clear_session();

    // Should not error out.
    env.binary()
        .arg("logout")
        .assert()
        .success()
        .stdout(predicate::str::contains("Not currently logged in"));
}

// ── unlock ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unlock_with_correct_password_succeeds() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    // Remove keys so vault starts locked.
    env.lock_vault();

    env.binary_with_password()
        .arg("unlock")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault unlocked"));

    // keys.json should now exist.
    assert!(
        env.config_dir.join("keys.json").exists(),
        "keys.json not written after unlock"
    );
}

#[tokio::test]
async fn unlock_with_wrong_password_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    env.binary()
        .args(["unlock", "--password", "totally-wrong-password"])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(password|decrypt|failed)").unwrap());
}

#[tokio::test]
async fn unlock_reads_password_from_env_var() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    env.binary()
        .arg("unlock")
        .env("VAULTWARDEN_PASSWORD", TEST_PASSWORD)
        .assert()
        .success()
        .stdout(predicate::str::contains("unlocked"));
}

// ── lock ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn lock_clears_vault_keys() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    // Vault starts unlocked (keys.json present).
    assert!(env.config_dir.join("keys.json").exists());

    env.binary()
        .arg("lock")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault locked"));

    // keys.json should be gone.
    assert!(
        !env.config_dir.join("keys.json").exists(),
        "keys.json still present after lock"
    );
}

#[tokio::test]
async fn lock_when_already_locked_is_graceful() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    // Should not error — lock is idempotent.
    env.binary().arg("lock").assert().success();
}

// ── vault commands require unlock ─────────────────────────────────────────

#[tokio::test]
async fn list_requires_vault_unlocked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    env.binary()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(lock|unlock|key)").unwrap());
}

#[tokio::test]
async fn get_requires_vault_unlocked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    env.binary()
        .args(["get", FIXTURE_LOGIN_NAME])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(lock|unlock|key)").unwrap());
}
