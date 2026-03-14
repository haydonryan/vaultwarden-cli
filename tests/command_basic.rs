mod support;

use predicates::prelude::*;
use support::TestContext;

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
