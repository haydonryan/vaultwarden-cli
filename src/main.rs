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

        /// Output format (json, env, value)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Show current session status
    Status,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Login { server, client_id, client_secret } => {
            println!("Login command");
            if let Some(s) = server {
                println!("  Server: {}", s);
            }
            if let Some(id) = client_id {
                println!("  Client ID: {}", id);
            }
            if client_secret.is_some() {
                println!("  Client secret: [provided]");
            }
        }
        Commands::Logout => {
            println!("Logout command");
        }
        Commands::List { r#type, search } => {
            println!("List command");
            if let Some(t) = r#type {
                println!("  Type: {}", t);
            }
            if let Some(s) = search {
                println!("  Search: {}", s);
            }
        }
        Commands::Get { item, format } => {
            println!("Get command");
            println!("  Item: {}", item);
            println!("  Format: {}", format);
        }
        Commands::Status => {
            println!("Status command");
        }
    }
}
