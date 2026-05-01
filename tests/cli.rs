#![allow(clippy::pedantic, clippy::nursery)]

mod support;

use predicates::prelude::*;
use support::TestContext;

#[test]
fn login_reads_client_credentials_from_environment() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("login")
        .arg("--server")
        .arg("http://127.0.0.1:9")
        .env("VAULTWARDEN_CLIENT_ID", "env-client")
        .env("VAULTWARDEN_CLIENT_SECRET", "env-secret")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to check server status"));
}

#[test]
fn get_uri_subcommand_name_parses() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("get-uri")
        .arg("example.com")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_uri_subcommand_name_parses() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run-uri")
        .arg("example.com")
        .arg("--")
        .arg("env")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_accepts_credential_name_alias() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("--credential-name")
        .arg("My App")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_accepts_multiple_name_flags() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("--name")
        .arg("Alpha")
        .arg("--name")
        .arg("Beta")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_parses_trailing_command_after_double_dash() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("--name")
        .arg("My App")
        .arg("--")
        .arg("echo")
        .arg("hello")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_accepts_implicit_name_before_double_dash() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("My App")
        .arg("--")
        .arg("echo")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_accepts_multiple_implicit_names_before_double_dash() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("My App")
        .arg("Other App")
        .arg("--")
        .arg("echo")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn run_accepts_comma_separated_implicit_names_before_double_dash() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("run")
        .arg("My App,Other App")
        .arg("--")
        .arg("echo")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}

#[test]
fn interpolate_accepts_output_file_option() {
    let ctx = TestContext::new();

    ctx.binary()
        .arg("interpolate")
        .arg("--file")
        .arg("config.yml")
        .arg("--output")
        .arg("rendered.yml")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not logged in"));
}
