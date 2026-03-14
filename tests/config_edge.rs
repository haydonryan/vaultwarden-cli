mod support;

use support::{env_lock, TestContext};
use vaultwarden_cli::config::Config;

#[test]
fn config_load_fails_for_invalid_config_json() {
    let _guard = env_lock();
    let ctx = TestContext::new();
    ctx.set_process_env();
    ctx.write_raw_config("{not-json").unwrap();

    let err = Config::load().err().expect("config load should fail");

    assert!(err.to_string().contains("Failed to parse config"));
}
