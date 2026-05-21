//! Live tests: `interpolate` — placeholder substitution for all field types,
//! output modes, skip-missing, and error paths.
//!
//! Placeholder format: `((item-name.field))` — double-paren, NOT curly braces.
#![allow(dead_code, clippy::pedantic, clippy::nursery)]

use crate::live_env::{
    LiveTestEnv, FIXTURE_LOGIN_FIELD_API_KEY_VALUE, FIXTURE_LOGIN_FIELD_SECRET_VALUE,
    FIXTURE_LOGIN_NAME, FIXTURE_LOGIN_PASSWORD, FIXTURE_LOGIN_URI, FIXTURE_LOGIN_USERNAME,
    FIXTURE_NOTE_CONTENT, FIXTURE_NOTE_NAME, FIXTURE_SSH_NAME, FIXTURE_SSH_PUBLIC_KEY,
};
use predicates::prelude::*;
use std::io::Write;

// ── helpers ───────────────────────────────────────────────────────────────

/// Write a template to a NamedTempFile and return (file, path-str).
fn write_template(content: &str) -> (tempfile::NamedTempFile, String) {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    let path = f.path().to_string_lossy().to_string();
    (f, path)
}

// ── password placeholder ──────────────────────────────────────────────────

#[tokio::test]
async fn interpolate_password_placeholder() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("password: (({FIXTURE_LOGIN_NAME}.password))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("password: {FIXTURE_LOGIN_PASSWORD}"),
        "password placeholder not substituted"
    );
}

// ── username placeholder ──────────────────────────────────────────────────

#[tokio::test]
async fn interpolate_username_placeholder() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("user: (({FIXTURE_LOGIN_NAME}.username))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), format!("user: {FIXTURE_LOGIN_USERNAME}"));
}

// ── URI placeholder ───────────────────────────────────────────────────────

#[tokio::test]
async fn interpolate_uri_placeholder() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("endpoint: (({FIXTURE_LOGIN_NAME}.uri))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), format!("endpoint: {FIXTURE_LOGIN_URI}"));
}

// ── custom field placeholder ──────────────────────────────────────────────

#[tokio::test]
async fn interpolate_custom_field() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("key: (({FIXTURE_LOGIN_NAME}.api_key))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("key: {FIXTURE_LOGIN_FIELD_API_KEY_VALUE}")
    );
}

// ── hidden / secret custom field ──────────────────────────────────────────

#[tokio::test]
async fn interpolate_hidden_custom_field() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("secret: (({FIXTURE_LOGIN_NAME}.secret))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("secret: {FIXTURE_LOGIN_FIELD_SECRET_VALUE}")
    );
}

// ── SSH public_key placeholder ────────────────────────────────────────────

#[tokio::test]
async fn interpolate_ssh_public_key() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("pubkey: (({FIXTURE_SSH_NAME}.public_key))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ssh-ed25519") || stdout.contains("live-test"),
        "SSH public key not substituted: {stdout}"
    );
}

// ── multiple placeholders in one file ────────────────────────────────────

#[tokio::test]
async fn interpolate_multiple_placeholders_in_one_template() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!(
        "u=(({FIXTURE_LOGIN_NAME}.username)) p=(({FIXTURE_LOGIN_NAME}.password))"
    );
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!("u={FIXTURE_LOGIN_USERNAME} p={FIXTURE_LOGIN_PASSWORD}")
    );
}

// ── missing placeholder without --skip-missing ────────────────────────────

#[tokio::test]
async fn interpolate_missing_placeholder_without_skip_fails() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = "((zzz-no-such-item-zzz.password))";
    let (_f, path) = write_template(template);

    env.binary()
        .args(["interpolate", "--file", &path])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(not found|missing|no item)").unwrap());
}

// ── missing placeholder with --skip-missing ───────────────────────────────

#[tokio::test]
async fn interpolate_missing_placeholder_with_skip_succeeds() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = "known=((Live-Test-Login.password)) unknown=((zzz-no-such-item.password))";
    let (_f, path) = write_template(template);

    let output = env
        .binary()
        .args(["interpolate", "--skip-missing", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Known placeholder should be resolved; unknown placeholder stays as-is or is blank.
    assert!(
        stdout.contains(FIXTURE_LOGIN_PASSWORD),
        "known placeholder not resolved: {stdout}"
    );
}

// ── output to file (--output flag) ────────────────────────────────────────

#[tokio::test]
async fn interpolate_output_to_file() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("pw=(({FIXTURE_LOGIN_NAME}.password))");
    let (_f, path) = write_template(&template);

    let out_file = tempfile::NamedTempFile::new().unwrap();
    let out_path = out_file.path().to_string_lossy().to_string();

    env.binary()
        .args(["interpolate", "--file", &path, "--output", &out_path])
        .assert()
        .success();

    let written = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(written.trim(), format!("pw={FIXTURE_LOGIN_PASSWORD}"));
}

// ── output to stdout (default) ────────────────────────────────────────────

#[tokio::test]
async fn interpolate_output_defaults_to_stdout() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("x=(({FIXTURE_LOGIN_NAME}.password))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FIXTURE_LOGIN_PASSWORD),
        "expected output on stdout: {stdout}"
    );
    // The HTTP warning may appear on stderr in test environments; real errors should not.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let unexpected_stderr: String = stderr
        .lines()
        .filter(|l| !l.starts_with("Warning:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        unexpected_stderr.trim().is_empty(),
        "unexpected stderr on success: {unexpected_stderr}"
    );
}

// ── case-insensitive item name lookup ────────────────────────────────────

#[tokio::test]
async fn interpolate_item_name_is_case_insensitive() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    // All-lowercase version of the item name.
    let lower = FIXTURE_LOGIN_NAME.to_lowercase();
    let template = format!("pw=(({lower}.password))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FIXTURE_LOGIN_PASSWORD),
        "case-insensitive lookup failed: {stdout}"
    );
}

// ── note content placeholder ──────────────────────────────────────────────

#[tokio::test]
async fn interpolate_note_notes_field() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };

    let template = format!("note: (({FIXTURE_NOTE_NAME}.notes))");
    let (_f, path) = write_template(&template);

    let output = env
        .binary()
        .args(["interpolate", "--file", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(FIXTURE_NOTE_CONTENT),
        "note content not substituted: {stdout}"
    );
}

// ── interpolate requires unlock ───────────────────────────────────────────

#[tokio::test]
async fn interpolate_requires_vault_unlocked() {
    let Some(env) = LiveTestEnv::maybe_create().await else {
        return;
    };
    env.lock_vault();

    let template = format!("(({FIXTURE_LOGIN_NAME}.password))");
    let (_f, path) = write_template(&template);

    env.binary()
        .args(["interpolate", "--file", &path])
        .assert()
        .failure()
        .stderr(predicate::str::is_match("(?i)(lock|unlock|key)").unwrap());
}
