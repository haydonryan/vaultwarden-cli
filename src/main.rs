use argy::{FromArgValue, FromArgs};
use vaultwarden_cli::commands::{self, OutputFormat};

type Result<T> = std::result::Result<T, anyhow::Error>;

/// CLI client for Vaultwarden - retrieve secrets for batch files and environment variables
#[derive(FromArgs)]
struct Cli {
    /// allow insecure HTTP connections (secrets sent unencrypted).
    /// also settable via `VAULTWARDEN_ALLOW_HTTP=1` env var.
    #[argy(switch, global)]
    allow_insecure_http: bool,

    /// allow decryption of ciphertext without MAC integrity verification.
    /// also settable via `VAULTWARDEN_ALLOW_INSECURE_MAC=1` env var.
    #[argy(switch, global)]
    allow_insecure_mac: bool,

    /// allow plaintext JSON secret output when stdout is redirected or captured.
    /// also settable via `VAULTWARDEN_ALLOW_PLAINTEXT_JSON=true` env var.
    #[argy(switch, global, env = "VAULTWARDEN_ALLOW_PLAINTEXT_JSON")]
    allow_plaintext_json: bool,

    #[argy(subcommand)]
    command: Commands,
}

#[derive(FromArgs)]
#[argy(subcommand)]
enum Commands {
    Login(LoginCommand),
    Unlock(UnlockCommand),
    Lock(LockCommand),
    Logout(LogoutCommand),
    List(ListCommand),
    Get(GetCommand),
    GetUri(GetUriCommand),
    Run(RunCommand),
    RunUri(RunUriCommand),
    Status(StatusCommand),
    Interpolate(InterpolateCommand),
}

#[derive(FromArgs)]
#[argy(subcommand, name = "login")]
/// login to Vaultwarden server
struct LoginCommand {
    /// server URL (e.g., <https://vaultwarden.example.com>)
    #[argy(option, short = 's')]
    server: Option<String>,

    /// client ID for API authentication
    #[argy(option, env = "VAULTWARDEN_CLIENT_ID")]
    client_id: Option<String>,

    /// client secret for API authentication
    #[argy(option, env = "VAULTWARDEN_CLIENT_SECRET")]
    client_secret: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "unlock")]
/// unlock the vault with master password
struct UnlockCommand {
    /// master password (falls back to `VAULTWARDEN_PASSWORD`, then prompts)
    #[argy(option, short = 'p', env = "VAULTWARDEN_PASSWORD")]
    password: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "lock")]
/// lock the vault (clear decryption keys)
struct LockCommand {}

#[derive(FromArgs)]
#[argy(subcommand, name = "logout")]
/// logout from Vaultwarden server
struct LogoutCommand {}

#[derive(FromArgs)]
#[argy(subcommand, name = "list")]
/// list items in the vault
struct ListCommand {
    /// object to list
    #[argy(positional)]
    object: Option<ListObject>,

    /// filter by item type (login, note, card, identity, ssh)
    #[argy(option, short = 't', long = "type")]
    r#type: Option<String>,

    /// output list results as JSON
    #[argy(switch)]
    json: bool,

    /// search term
    #[argy(option, short = 's')]
    search: Option<String>,

    /// filter by organization name or ID
    #[argy(option)]
    org: Option<String>,

    /// filter by collection name or ID
    #[argy(option, short = 'c')]
    collection: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "get")]
/// get a specific item or secret
struct GetCommand {
    /// item ID or name to retrieve
    #[argy(positional)]
    item: String,

    /// query for two-position get operations
    #[argy(positional)]
    query: Option<String>,

    /// output format
    #[argy(option, short = 'f', default = "OutputFormat::Json")]
    format: OutputFormat,

    /// output only the username (shorthand for --format username)
    #[argy(switch, short = 'u')]
    username: bool,

    /// output only the password (shorthand for --format value)
    #[argy(switch, short = 'p')]
    password: bool,

    /// filter by organization name or ID
    #[argy(option)]
    org: Option<String>,

    /// filter by collection name or ID
    #[argy(option)]
    collection: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "get-uri")]
/// get a specific item by URI
struct GetUriCommand {
    /// URI to search for (e.g., github.com)
    #[argy(positional)]
    uri: String,

    /// output format
    #[argy(option, short = 'f', default = "OutputFormat::Json")]
    format: OutputFormat,

    /// output only the username (shorthand for --format username)
    #[argy(switch, short = 'u')]
    username: bool,

    /// output only the password (shorthand for --format value)
    #[argy(switch, short = 'p')]
    password: bool,

    /// filter by organization name or ID
    #[argy(option)]
    org: Option<String>,

    /// filter by collection name or ID
    #[argy(option)]
    collection: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "run")]
/// run a command with secrets injected as environment variables
struct RunCommand {
    /// item name or ID to inject (repeat flag or use commas for multiple)
    #[argy(option, alias = "credential-name", value_delimiter = ',')]
    name: Vec<String>,

    /// item name or ID to inject when no selector flag is provided
    #[argy(positional, last)]
    item: Vec<String>,

    /// filter by organization name or ID
    #[argy(option)]
    org: Option<String>,

    /// filter by folder name or ID
    #[argy(option)]
    folder: Option<String>,

    /// filter by collection name or ID
    #[argy(option)]
    collection: Option<String>,

    /// print list of injected environment variables without values
    #[argy(switch, short = 'i')]
    info: bool,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "run-uri")]
/// run a command with secrets from URI match injected as environment variables
struct RunUriCommand {
    /// URI to search for
    #[argy(positional)]
    uri: String,

    /// print list of injected environment variables without values
    #[argy(switch, short = 'i')]
    info: bool,

    /// command to run (use -- to separate from vaultwarden-cli args)
    #[argy(positional, last)]
    command: Vec<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "status")]
/// show current session status
struct StatusCommand {}

#[derive(FromArgs)]
#[argy(subcommand, name = "interpolate")]
/// interpolate secrets into a YAML file
struct InterpolateCommand {
    /// YAML file to interpolate
    #[argy(option, short = 'f')]
    file: String,

    /// write the interpolated output to a file instead of stdout
    #[argy(option, short = 'o')]
    output: Option<String>,

    /// skip missing secrets and leave placeholders unchanged
    #[argy(switch, short = 's')]
    skip_missing: bool,
}

#[derive(Debug, Clone, Copy, FromArgValue, PartialEq, Eq)]
enum ListObject {
    Items,
}

const fn effective_format(format: OutputFormat, username: bool, password: bool) -> OutputFormat {
    if username {
        OutputFormat::Username
    } else if password {
        OutputFormat::Value
    } else {
        format
    }
}

#[tokio::main]
async fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    let raw_strs: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    let cli: Cli = argy::from_env();
    let result = run_cli(cli, &raw_strs).await;

    if let Err(e) = &result {
        eprintln!("Error: {e:#}");
    }
    let exit_code = result_exit_code(&result);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn result_exit_code(result: &Result<commands::CommandOutcome>) -> i32 {
    result
        .as_ref()
        .map_or(1, commands::CommandOutcome::exit_code)
}

/// return the args that follow `subcommand` in `raw` (which includes the program
/// name at index 0). Global `--` switches declared on the top-level `Cli` are
/// skipped so the subcommand token is located.
fn subcommand_args<'a>(raw: &'a [&'a str], subcommand: &str) -> Vec<&'a str> {
    let mut i = 1;
    while i < raw.len() && raw[i].starts_with('-') && raw[i] != "--" {
        i += 1;
    }
    let start = if i < raw.len() && raw[i] == subcommand {
        i + 1
    } else {
        i
    };
    raw[start.min(raw.len())..].to_vec()
}

/// argy captures the `item` selectors and the trailing `command` into a single
/// `last` positional. Split them back out using the raw subcommand args:
/// everything after the `--` separator is the command; the rest are item
/// selectors, which are comma-split to mirror clap's `value_delimiter`.
fn split_run_trailing(item: &[String], run_args: &[&str]) -> (Vec<String>, Vec<String>) {
    let sep = run_args.iter().position(|a| *a == "--");
    let command_len = sep.map_or(0, |idx| run_args.len() - idx - 1);
    let split_at = item.len().saturating_sub(command_len);
    let command = item[split_at..].to_vec();
    let item = item[..split_at]
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::to_string)
        .collect();
    (item, command)
}

#[allow(clippy::too_many_lines)]
async fn run_cli(cli: Cli, raw_args: &[&str]) -> Result<commands::CommandOutcome> {
    // Propagate global security flags to library code
    vaultwarden_cli::crypto::set_allow_insecure_mac(cli.allow_insecure_mac);

    let opts = commands::CommandOptions::for_cli(cli.allow_insecure_http, cli.allow_plaintext_json);

    match cli.command {
        Commands::Login(LoginCommand {
            server,
            client_id,
            client_secret,
        }) => commands::login(server, client_id, client_secret, &opts)
            .await
            .map(|_| commands::CommandOutcome::Success),
        Commands::Unlock(UnlockCommand { password }) => commands::unlock(password, &opts)
            .await
            .map(|_| commands::CommandOutcome::Success),
        Commands::Lock(LockCommand {}) => commands::lock()
            .map(|_| commands::CommandOutcome::Success),
        Commands::Logout(LogoutCommand {}) => commands::logout()
            .map(|_| commands::CommandOutcome::Success),
        Commands::List(ListCommand {
            object,
            r#type,
            search,
            org,
            collection,
            json,
        }) => {
            if object.is_some() {
                commands::list_items(r#type, search, org, collection, &opts).await
            } else {
                commands::list(r#type, search, org, collection, json, &opts).await
            }
            .map(|()| commands::CommandOutcome::Success)
        }
        Commands::Get(GetCommand {
            item,
            query,
            format,
            username,
            password,
            org,
            collection,
        }) => {
            if let Some(query) = query {
                if !item.eq_ignore_ascii_case("totp") {
                    anyhow::bail!(
                        "Unknown two-position get form '{item} <query>'; supported form: get totp <id-or-search>"
                    );
                }
                if username
                    || password
                    || format != OutputFormat::Json
                    || org.is_some()
                    || collection.is_some()
                {
                    anyhow::bail!("get totp does not support legacy get output or scope options");
                }
                commands::get_totp(&query, &opts).await
            } else {
                commands::get(
                    &item,
                    effective_format(format, username, password),
                    org,
                    collection,
                    &opts,
                )
                .await
            }
            .map(|()| commands::CommandOutcome::Success)
        }
        Commands::GetUri(GetUriCommand {
            uri,
            format,
            username,
            password,
            org,
            collection,
        }) => commands::get_by_uri(
            &uri,
            effective_format(format, username, password),
            org,
            collection,
            &opts,
        )
        .await
        .map(|()| commands::CommandOutcome::Success),
        Commands::Run(RunCommand {
            name,
            item,
            org,
            folder,
            collection,
            info,
        }) => {
            let run_args = subcommand_args(raw_args, "run");
            let (item, command) = split_run_trailing(&item, &run_args);
            let requested_items =
                if name.is_empty() && org.is_none() && folder.is_none() && collection.is_none() {
                    item
                } else {
                    name
                };
            commands::run_with_secrets(commands::RunOptions {
                requested_items: &requested_items,
                search_by_uri: false,
                org_filter: org.as_deref(),
                folder_filter: folder.as_deref(),
                collection_filter: collection.as_deref(),
                info_only: info,
                command: &command,
                opts: &opts,
            })
            .await
        }
        Commands::RunUri(RunUriCommand { uri, info, command }) => {
            commands::run_with_secrets(commands::RunOptions {
                requested_items: &[uri],
                search_by_uri: true,
                org_filter: None,
                folder_filter: None,
                collection_filter: None,
                info_only: info,
                command: &command,
                opts: &opts,
            })
            .await
        }
        Commands::Status(StatusCommand {}) => commands::status()
            .map(|()| commands::CommandOutcome::Success),
        Commands::Interpolate(InterpolateCommand {
            file,
            output,
            skip_missing,
        }) => commands::interpolate(&file, output.as_deref(), skip_missing, &opts)
            .await
            .map(|()| commands::CommandOutcome::Success),
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;
    use vaultwarden_cli::config::{Config, ConfigDirOverride};
    use vaultwarden_cli::crypto::CryptoKeys;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestEnv {
        _guard: MutexGuard<'static, ()>,
        temp_dir: TempDir,
        _config_dir_override: ConfigDirOverride,
        config_dir: std::path::PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let guard = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let temp_dir = TempDir::new().expect("create temp dir");
            let config_root = temp_dir.path().join("config-root");
            std::fs::create_dir_all(&config_root).expect("create config root");
            let config_dir = config_root.join("vaultwarden-cli");

            let config_dir_override = Config::scoped_config_dir_override_for_thread(&config_dir);
            unsafe {
                std::env::set_var("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE", "true");
            }

            Self {
                _guard: guard,
                temp_dir,
                _config_dir_override: config_dir_override,
                config_dir,
            }
        }

        fn config_dir(&self) -> std::path::PathBuf {
            self.config_dir.clone()
        }

        fn write_config(&self, config: &Config) {
            std::fs::create_dir_all(&self.config_dir).expect("create config dir");
            config.save().expect("save config");
            if config.crypto_keys.is_some() || !config.org_crypto_keys.is_empty() {
                config.save_keys().expect("save keys");
            }
        }

        fn fixture_file(&self, name: &str, contents: &str) -> String {
            let path = self.temp_dir.path().join(name);
            std::fs::write(&path, contents).expect("write fixture");
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("VAULTWARDEN_ALLOW_INSECURE_KEY_FILE");
            }
        }
    }

    fn logged_in_config(server: String) -> Config {
        Config {
            server: Some(server),
            access_token: Some("access-token".to_string()),
            token_expiry: Some(i64::MAX),
            crypto_keys: Some(CryptoKeys::from_key_bytes([0u8; 32], [0u8; 32])),
            ..Default::default()
        }
    }

    async fn mock_empty_sync() -> MockServer {
        let mock_server = MockServer::start().await;
        let sync_response = serde_json::json!({
            "Ciphers": [],
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
            .mount(&mock_server)
            .await;

        mock_server
    }

    #[test]
    fn test_effective_format_username_override() {
        assert_eq!(
            effective_format(OutputFormat::Json, true, false),
            OutputFormat::Username
        );
    }

    #[test]
    fn test_effective_format_password_override() {
        assert_eq!(
            effective_format(OutputFormat::Json, false, true),
            OutputFormat::Value
        );
    }

    #[test]
    fn test_effective_format_no_override() {
        assert_eq!(
            effective_format(OutputFormat::Env, false, false),
            OutputFormat::Env
        );
        assert_eq!(
            effective_format(OutputFormat::Json, false, false),
            OutputFormat::Json
        );
    }

    /// parse `args` (without a program name) and return the parsed `Cli` plus
    /// the full argv (program name included) needed by `run_cli`.
    fn parse_cli<'a>(args: &'a [&'a str]) -> (Cli, Vec<&'a str>) {
        let mut full = vec!["vaultwarden-cli"];
        full.extend_from_slice(args);
        let cli = Cli::from_args(&["vaultwarden-cli"], args).expect("parse cli");
        (cli, full)
    }

    #[test]
    fn test_cli_global_allow_plaintext_json_parsing() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["--allow-plaintext-json", "status"])
            .expect("parse cli");

        assert!(cli.allow_plaintext_json);
    }

    #[test]
    fn test_result_exit_code_success() {
        assert_eq!(result_exit_code(&Ok(commands::CommandOutcome::Success)), 0);
    }

    #[test]
    fn test_result_exit_code_error() {
        assert_eq!(result_exit_code(&Err(anyhow::anyhow!("failure"))), 1);
    }

    #[test]
    fn test_result_exit_code_child_status() {
        let status = std::process::Command::new("false").status().unwrap();

        assert_eq!(
            result_exit_code(&Ok(commands::CommandOutcome::ChildExit(status))),
            1
        );
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_status_success() {
        let _env = TestEnv::new();
        let (cli, raw) = parse_cli(&["status"]);

        run_cli(cli, &raw).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_cli_propagates_command_errors() {
        let _env = TestEnv::new();
        let (cli, raw) = parse_cli(&["run"]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("At least one of --name, --org, --folder, or --collection")
        );
    }

    #[tokio::test]
    async fn test_run_cli_reports_config_load_errors() {
        let env = TestEnv::new();
        std::fs::create_dir_all(env.config_dir()).unwrap();
        std::fs::write(env.config_dir().join("config.json"), "{not-json").unwrap();
        let (cli, raw) = parse_cli(&["status"]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(err.to_string().contains("Failed to parse config"));
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_list_with_insecure_http_flag() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&["--allow-insecure-http", "list"]);

        run_cli(cli, &raw).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_cli_rejects_list_without_insecure_http_flag() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&["list"]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(err.to_string().contains("Insecure server URL rejected"));
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_get_through_sync_lookup() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&[
            "--allow-insecure-http",
            "get",
            "missing-item",
            "--format",
            "env",
            "--collection",
            "missing-collection",
        ]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("Collection 'missing-collection' not found")
        );
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_get_uri_through_sync_lookup() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&[
            "--allow-insecure-http",
            "get-uri",
            "https://example.com",
            "--format",
            "env",
        ]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        let err = err.to_string();
        assert!(!err.is_empty());
        assert!(err.to_lowercase().contains("uri"));
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_run_with_explicit_name() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&[
            "--allow-insecure-http",
            "run",
            "--name",
            "missing-item",
            "--info",
        ]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(err.to_string().contains("Item 'missing-item' not found"));
    }

    #[tokio::test]
    async fn test_run_cli_uses_positional_run_items_only_without_explicit_selector() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&[
            "--allow-insecure-http",
            "run",
            "implicit-item",
            "--name",
            "explicit-item",
            "--info",
        ]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        assert!(err.to_string().contains("Item 'explicit-item' not found"));
        assert!(!err.to_string().contains("implicit-item"));
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_run_uri() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let (cli, raw) = parse_cli(&[
            "--allow-insecure-http",
            "run-uri",
            "https://example.com",
            "--info",
        ]);

        let err = run_cli(cli, &raw).await.unwrap_err();

        let err = err.to_string();
        assert!(!err.is_empty());
        assert!(err.to_lowercase().contains("uri"));
    }

    #[tokio::test]
    async fn test_run_cli_dispatches_interpolate() {
        let env = TestEnv::new();
        let mock_server = mock_empty_sync().await;
        env.write_config(&logged_in_config(mock_server.uri()));
        let file = env.fixture_file("input.yml", "plain: value\n");
        let args = ["--allow-insecure-http", "interpolate", "--file", &file];
        let (cli, raw) = parse_cli(&args);

        run_cli(cli, &raw).await.unwrap();
    }

    #[tokio::test]
    async fn test_run_cli_sets_insecure_mac_library_state() {
        let _env = TestEnv::new();
        vaultwarden_cli::crypto::set_allow_insecure_mac(false);
        let (cli, raw) = parse_cli(&["--allow-insecure-mac", "status"]);

        run_cli(cli, &raw).await.unwrap();

        assert!(vaultwarden_cli::crypto::allow_insecure_mac());
        vaultwarden_cli::crypto::set_allow_insecure_mac(false);
    }

    #[test]
    fn test_cli_plaintext_json_flag_reaches_command_options() {
        let cli = Cli::from_args(
            &["vaultwarden-cli"],
            &["--allow-plaintext-json", "list", "--json"],
        )
        .expect("parse cli");
        let opts =
            commands::CommandOptions::for_cli(cli.allow_insecure_http, cli.allow_plaintext_json);

        assert!(opts.allow_plaintext_json);
    }

    #[test]
    fn test_cli_login_parsing() {
        let cli = Cli::from_args(
            &["vaultwarden-cli"],
            &["login", "--server", "https://example.com"],
        )
        .expect("parse cli");
        let Commands::Login(LoginCommand {
            server,
            client_id,
            client_secret,
        }) = cli.command
        else {
            panic!("expected Login command");
        };
        assert_eq!(server, Some("https://example.com".to_string()));
        assert_eq!(client_id, None);
        assert_eq!(client_secret, None);
    }

    #[test]
    fn test_cli_unlock_parsing() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["unlock", "--password", "secret"])
            .expect("parse cli");
        let Commands::Unlock(UnlockCommand { password }) = cli.command else {
            panic!("expected Unlock command");
        };
        assert_eq!(password, Some("secret".to_string()));
    }

    #[test]
    fn test_cli_get_username_flag_overrides_format() {
        let cli = Cli::from_args(
            &["vaultwarden-cli"],
            &["get", "item-name", "--format", "json", "--username"],
        )
        .expect("parse cli");
        let Commands::Get(GetCommand {
            item,
            query,
            format,
            username,
            password,
            org,
            collection,
        }) = cli.command
        else {
            panic!("expected Get command");
        };
        assert_eq!(item, "item-name");
        assert_eq!(query, None);
        assert!(username);
        assert!(!password);
        assert_eq!(format, OutputFormat::Json);
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_get_password_flag_overrides_format() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["get", "item-name", "--password"])
            .expect("parse cli");
        let Commands::Get(GetCommand {
            item,
            query,
            format,
            username,
            password,
            org,
            collection,
        }) = cli.command
        else {
            panic!("expected Get command");
        };
        assert_eq!(item, "item-name");
        assert_eq!(query, None);
        assert!(!username);
        assert!(password);
        assert_eq!(format, OutputFormat::Json); // default
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_list_parsing_with_json() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["list", "--json"]).expect("parse cli");
        let Commands::List(ListCommand {
            object,
            r#type,
            json,
            search,
            org,
            collection,
        }) = cli.command
        else {
            panic!("expected List command");
        };
        assert_eq!(object, None);
        assert_eq!(r#type, None);
        assert!(json);
        assert_eq!(search, None);
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_get_totp_two_position_parsing() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["get", "totp", "item-search"])
            .expect("parse cli");
        let Commands::Get(GetCommand { item, query, .. }) = cli.command else {
            panic!("expected Get command");
        };

        assert_eq!(item, "totp");
        assert_eq!(query.as_deref(), Some("item-search"));
    }

    #[test]
    fn test_cli_list_items_parsing() {
        let cli = Cli::from_args(&["vaultwarden-cli"], &["list", "items"]).expect("parse cli");
        let Commands::List(ListCommand { object, json, .. }) = cli.command else {
            panic!("expected List command");
        };

        assert_eq!(object, Some(ListObject::Items));
        assert!(!json);
    }

    #[test]
    fn test_cli_list_rejects_unsupported_object() {
        let Err(err) = Cli::from_args(&["vaultwarden-cli"], &["list", "folders"]) else {
            panic!("unsupported list object should be rejected");
        };

        assert!(err.output.contains("expected \"items\""));
    }

    #[test]
    fn test_cli_get_uri_parsing() {
        let cli = Cli::from_args(
            &["vaultwarden-cli"],
            &["get-uri", "example.com", "--format", "env"],
        )
        .expect("parse cli");
        let Commands::GetUri(GetUriCommand {
            uri,
            format,
            username,
            password,
            org,
            collection,
        }) = cli.command
        else {
            panic!("expected GetUri command");
        };
        assert_eq!(uri, "example.com");
        assert_eq!(format, OutputFormat::Env);
        assert!(!username);
        assert!(!password);
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_run_parsing() {
        let args = ["run", "--name", "My App", "--", "echo", "hello"];
        let cli = Cli::from_args(&["vaultwarden-cli"], &args).expect("parse cli");
        let Commands::Run(RunCommand {
            name,
            item,
            org,
            folder,
            collection,
            info,
        }) = cli.command
        else {
            panic!("expected Run command");
        };
        let mut full = vec!["vaultwarden-cli"];
        full.extend_from_slice(&args);
        let run_args = subcommand_args(&full, "run");
        let (item, command) = split_run_trailing(&item, &run_args);

        assert_eq!(name, vec!["My App".to_string()]);
        assert!(item.is_empty());
        assert_eq!(org, None);
        assert_eq!(folder, None);
        assert_eq!(collection, None);
        assert!(!info);
        assert_eq!(command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_cli_run_parsing_with_implicit_name() {
        let args = ["run", "My App", "--", "echo", "hello"];
        let cli = Cli::from_args(&["vaultwarden-cli"], &args).expect("parse cli");
        let Commands::Run(RunCommand {
            name,
            item,
            org,
            folder,
            collection,
            info,
        }) = cli.command
        else {
            panic!("expected Run command");
        };
        let mut full = vec!["vaultwarden-cli"];
        full.extend_from_slice(&args);
        let run_args = subcommand_args(&full, "run");
        let (item, command) = split_run_trailing(&item, &run_args);

        assert!(name.is_empty());
        assert_eq!(item, vec!["My App".to_string()]);
        assert_eq!(org, None);
        assert_eq!(folder, None);
        assert_eq!(collection, None);
        assert!(!info);
        assert_eq!(command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_cli_run_parsing_with_multiple_implicit_names() {
        let args = ["run", "My App", "Other App", "--", "echo", "hello"];
        let cli = Cli::from_args(&["vaultwarden-cli"], &args).expect("parse cli");
        let Commands::Run(RunCommand {
            name,
            item,
            org,
            folder,
            collection,
            info,
        }) = cli.command
        else {
            panic!("expected Run command");
        };
        let mut full = vec!["vaultwarden-cli"];
        full.extend_from_slice(&args);
        let run_args = subcommand_args(&full, "run");
        let (item, command) = split_run_trailing(&item, &run_args);

        assert!(name.is_empty());
        assert_eq!(item, vec!["My App".to_string(), "Other App".to_string()]);
        assert_eq!(org, None);
        assert_eq!(folder, None);
        assert_eq!(collection, None);
        assert!(!info);
        assert_eq!(command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_cli_run_parsing_with_comma_separated_implicit_names() {
        let args = ["run", "My App,Other App", "--", "echo", "hello"];
        let cli = Cli::from_args(&["vaultwarden-cli"], &args).expect("parse cli");
        let Commands::Run(RunCommand {
            name,
            item,
            org,
            folder,
            collection,
            info,
        }) = cli.command
        else {
            panic!("expected Run command");
        };
        let mut full = vec!["vaultwarden-cli"];
        full.extend_from_slice(&args);
        let run_args = subcommand_args(&full, "run");
        let (item, command) = split_run_trailing(&item, &run_args);

        assert!(name.is_empty());
        assert_eq!(item, vec!["My App".to_string(), "Other App".to_string()]);
        assert_eq!(org, None);
        assert_eq!(folder, None);
        assert_eq!(collection, None);
        assert!(!info);
        assert_eq!(command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_cli_interpolate_parsing() {
        let cli = Cli::from_args(
            &["vaultwarden-cli"],
            &[
                "interpolate",
                "--file",
                "config.yml",
                "--output",
                "rendered.yml",
                "--skip-missing",
            ],
        )
        .expect("parse cli");
        let Commands::Interpolate(InterpolateCommand {
            file,
            output,
            skip_missing,
        }) = cli.command
        else {
            panic!("expected Interpolate command");
        };
        assert_eq!(file, "config.yml");
        assert_eq!(output, Some("rendered.yml".to_string()));
        assert!(skip_missing);
    }
}
