mod support;

use predicates::prelude::*;
use support::{test_crypto_keys, TestContext};
use vaultwarden_cli::config::Config;

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
