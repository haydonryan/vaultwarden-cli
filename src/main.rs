use clap::{Parser, Subcommand};
use vaultwarden_cli::commands;

#[derive(Parser)]
#[command(name = "vaultwarden-cli")]
#[command(
    about = "CLI client for Vaultwarden - retrieve secrets for batch files and environment variables"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Login to Vaultwarden server
    Login {
        /// Server URL (e.g., https://vaultwarden.example.com)
        #[arg(short, long)]
        server: Option<String>,

        /// Client ID for API authentication
        #[arg(long, env = "VAULTWARDEN_CLIENT_ID")]
        client_id: Option<String>,

        /// Client secret for API authentication
        #[arg(long, env = "VAULTWARDEN_CLIENT_SECRET")]
        client_secret: Option<String>,
    },

    /// Unlock the vault with master password
    Unlock {
        /// Master password (falls back to VAULTWARDEN_PASSWORD, then prompts)
        #[arg(short, long, env = "VAULTWARDEN_PASSWORD")]
        password: Option<String>,
    },

    /// Lock the vault (clear decryption keys)
    Lock,

    /// Logout from Vaultwarden server
    Logout,

    /// List items in the vault
    List {
        /// Filter by item type (login, note, card, identity, ssh)
        #[arg(short, long)]
        r#type: Option<String>,

        /// Search term
        #[arg(short, long)]
        search: Option<String>,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(short, long)]
        collection: Option<String>,
    },

    /// Get a specific item or secret
    Get {
        /// Item ID or name to retrieve
        item: String,

        /// Output format (json, env, value, username)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output only the username (shorthand for --format username)
        #[arg(short, long)]
        username: bool,

        /// Output only the password (shorthand for --format value)
        #[arg(short, long)]
        password: bool,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,
    },

    /// Get a specific item by URI
    #[command(name = "get-uri")]
    GetUri {
        /// URI to search for (e.g., github.com)
        uri: String,

        /// Output format (json, env, value, username)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output only the username (shorthand for --format username)
        #[arg(short, long)]
        username: bool,

        /// Output only the password (shorthand for --format value)
        #[arg(short, long)]
        password: bool,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,
    },

    /// Run a command with secrets injected as environment variables
    Run {
        /// Item name or ID to inject (comma-separated for multiple)
        #[arg(long, alias = "credential-name")]
        name: Option<String>,

        /// Filter by organization name or ID
        #[arg(long)]
        org: Option<String>,

        /// Filter by folder name or ID
        #[arg(long)]
        folder: Option<String>,

        /// Filter by collection name or ID
        #[arg(long)]
        collection: Option<String>,

        /// Print list of injected environment variables without values
        #[arg(short, long)]
        info: bool,

        /// Command to run (use -- to separate from vaultwarden-cli args)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Run a command with secrets from URI match injected as environment variables
    #[command(name = "run-uri")]
    RunUri {
        /// URI to search for
        uri: String,

        /// Print list of injected environment variables without values
        #[arg(short, long)]
        info: bool,

        /// Command to run (use -- to separate from vaultwarden-cli args)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Show current session status
    Status,

    /// Interpolate secrets into a YAML file
    Interpolate {
        /// YAML file to interpolate
        #[arg(short, long)]
        file: String,

        /// Write the interpolated output to a file instead of stdout
        #[arg(short, long)]
        output: Option<String>,

        /// Skip missing secrets and leave placeholders unchanged
        #[arg(short = 's', long)]
        skip_missing: bool,
    },
}

fn effective_format(format: &str, username: bool, password: bool) -> &str {
    if username {
        "username"
    } else if password {
        "value"
    } else {
        format
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Login {
            server,
            client_id,
            client_secret,
        } => commands::login(server, client_id, client_secret).await,
        Commands::Unlock { password } => commands::unlock(password).await,
        Commands::Lock => commands::lock().await,
        Commands::Logout => commands::logout().await,
        Commands::List {
            r#type,
            search,
            org,
            collection,
        } => commands::list(r#type, search, org, collection).await,
        Commands::Get {
            item,
            format,
            username,
            password,
            org,
            collection,
        } => {
            commands::get(
                &item,
                effective_format(&format, username, password),
                org,
                collection,
            )
            .await
        }
        Commands::GetUri {
            uri,
            format,
            username,
            password,
            org,
            collection,
        } => {
            commands::get_by_uri(
                &uri,
                effective_format(&format, username, password),
                org,
                collection,
            )
            .await
        }
        Commands::Run {
            name,
            org,
            folder,
            collection,
            info,
            command,
        } => {
            commands::run_with_secrets(
                name.as_deref(),
                false,
                org.as_deref(),
                folder.as_deref(),
                collection.as_deref(),
                info,
                &command,
            )
            .await
        }
        Commands::RunUri { uri, info, command } => {
            commands::run_with_secrets(Some(&uri), true, None, None, None, info, &command).await
        }
        Commands::Status => commands::status().await,
        Commands::Interpolate {
            file,
            output,
            skip_missing,
        } => commands::interpolate(&file, output.as_deref(), skip_missing).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_format_username_override() {
        assert_eq!(effective_format("json", true, false), "username");
    }

    #[test]
    fn test_effective_format_password_override() {
        assert_eq!(effective_format("json", false, true), "value");
    }

    #[test]
    fn test_effective_format_no_override() {
        assert_eq!(effective_format("env", false, false), "env");
        assert_eq!(effective_format("json", false, false), "json");
    }

    #[test]
    fn test_cli_login_parsing() {
        let cli = Cli::parse_from([
            "vaultwarden-cli",
            "login",
            "--server",
            "https://example.com",
        ]);
        let Commands::Login {
            server,
            client_id,
            client_secret,
        } = cli.command
        else {
            panic!("expected Login command");
        };
        assert_eq!(server, Some("https://example.com".to_string()));
        assert_eq!(client_id, None);
        assert_eq!(client_secret, None);
    }

    #[test]
    fn test_cli_unlock_parsing() {
        let cli = Cli::parse_from(["vaultwarden-cli", "unlock", "--password", "secret"]);
        let Commands::Unlock { password } = cli.command else {
            panic!("expected Unlock command");
        };
        assert_eq!(password, Some("secret".to_string()));
    }

    #[test]
    fn test_cli_get_username_flag_overrides_format() {
        let cli = Cli::parse_from([
            "vaultwarden-cli",
            "get",
            "item-name",
            "--format",
            "json",
            "--username",
        ]);
        let Commands::Get {
            item,
            format,
            username,
            password,
            org,
            collection,
        } = cli.command
        else {
            panic!("expected Get command");
        };
        assert_eq!(item, "item-name");
        assert!(username);
        assert!(!password);
        assert_eq!(format, "json");
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_get_password_flag_overrides_format() {
        let cli = Cli::parse_from(["vaultwarden-cli", "get", "item-name", "--password"]);
        let Commands::Get {
            item,
            format,
            username,
            password,
            org,
            collection,
        } = cli.command
        else {
            panic!("expected Get command");
        };
        assert_eq!(item, "item-name");
        assert!(!username);
        assert!(password);
        assert_eq!(format, "json"); // default
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_get_uri_parsing() {
        let cli = Cli::parse_from([
            "vaultwarden-cli",
            "get-uri",
            "example.com",
            "--format",
            "env",
        ]);
        let Commands::GetUri {
            uri,
            format,
            username,
            password,
            org,
            collection,
        } = cli.command
        else {
            panic!("expected GetUri command");
        };
        assert_eq!(uri, "example.com");
        assert_eq!(format, "env");
        assert!(!username);
        assert!(!password);
        assert_eq!(org, None);
        assert_eq!(collection, None);
    }

    #[test]
    fn test_cli_run_parsing() {
        let cli = Cli::parse_from([
            "vaultwarden-cli",
            "run",
            "--name",
            "My App",
            "--",
            "echo",
            "hello",
        ]);
        let Commands::Run {
            name,
            org,
            folder,
            collection,
            info,
            command,
        } = cli.command
        else {
            panic!("expected Run command");
        };
        assert_eq!(name, Some("My App".to_string()));
        assert_eq!(org, None);
        assert_eq!(folder, None);
        assert_eq!(collection, None);
        assert!(!info);
        assert_eq!(command, vec!["echo", "hello"]);
    }

    #[test]
    fn test_cli_interpolate_parsing() {
        let cli = Cli::parse_from([
            "vaultwarden-cli",
            "interpolate",
            "--file",
            "config.yml",
            "--output",
            "rendered.yml",
            "--skip-missing",
        ]);
        let Commands::Interpolate {
            file,
            output,
            skip_missing,
        } = cli.command
        else {
            panic!("expected Interpolate command");
        };
        assert_eq!(file, "config.yml");
        assert_eq!(output, Some("rendered.yml".to_string()));
        assert!(skip_missing);
    }
}
