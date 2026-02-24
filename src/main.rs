mod api;
mod commands;
mod config;
mod crypto;
mod models;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vaultwarden-cli")]
#[command(about = "CLI client for Vaultwarden - retrieve secrets for batch files and environment variables")]
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
        #[arg(long)]
        client_id: Option<String>,

        /// Client secret for API authentication
        #[arg(long)]
        client_secret: Option<String>,
    },

    /// Unlock the vault with master password
    Unlock {
        /// Master password (will prompt if not provided)
        #[arg(short, long)]
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
    },

    /// Get a specific item or secret
    Get {
        /// Item ID or name to retrieve
        item: String,

        /// Output format (json, env, value, username)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Show current session status
    Status,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Login { server, client_id, client_secret } => {
            commands::login(server, client_id, client_secret).await
        }
        Commands::Unlock { password } => {
            commands::unlock(password).await
        }
        Commands::Lock => {
            commands::lock().await
        }
        Commands::Logout => {
            commands::logout().await
        }
        Commands::List { r#type, search } => {
            commands::list(r#type, search).await
        }
        Commands::Get { item, format } => {
            commands::get(&item, &format).await
        }
        Commands::Status => {
            commands::status().await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
