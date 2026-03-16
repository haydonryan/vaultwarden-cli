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
        /// Filter by item type (login, note, card, identity)
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
            // --username and --password flags override --format
            let effective_format = if username {
                "username"
            } else if password {
                "value"
            } else {
                &format
            };
            commands::get(&item, effective_format, org, collection).await
        }
        Commands::GetUri {
            uri,
            format,
            username,
            password,
            org,
            collection,
        } => {
            // --username and --password flags override --format
            let effective_format = if username {
                "username"
            } else if password {
                "value"
            } else {
                &format
            };
            commands::get_by_uri(&uri, effective_format, org, collection).await
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
