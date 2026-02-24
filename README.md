# vaultwarden-cli

A pure Rust command-line client for [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-compatible server). Retrieve secrets from your vault for use in shell scripts, environment variables, and automation workflows.

## Why Rust?

This project is intentionally built in pure Rust rather than Node.js. Command-line tools should be fast, self-contained, and have minimal dependencies. Node.js CLI tools require a runtime, have slow startup times, and bring along thousands of transitive dependencies. Rust compiles to a single static binary that starts instantly and has zero runtime dependencies.

Additionally, this uses the system certificate store for TLS verification, not a bundled certificate store like Node.js. This means it respects your system's CA certificates and corporate proxy configurations out of the box.

## Features

- OAuth2 client credentials authentication
- PBKDF2 key derivation (configurable iterations)
- AES-256-CBC + HMAC-SHA256 decryption (Bitwarden-compatible)
- RSA-OAEP decryption for organization vault items
- Persistent sessions with secure credential storage
- Multiple output formats: JSON, environment exports, raw values
- Search and filter vault items

## Installation

### From Source

```bash
git clone https://github.com/yourusername/vaultwarden-cli.git
cd vaultwarden-cli
cargo build --release
```

The binary will be at `target/release/vaultwarden-cli`.

## Usage

### Authentication

First, create an API key in your Vaultwarden/Bitwarden web vault under Settings > Security > Keys > API Key.

```bash
# Login with your API credentials
vaultwarden-cli login \
  --server https://your-vaultwarden-server.com \
  --client-id "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --client-secret "your-client-secret"

# Unlock the vault with your master password
vaultwarden-cli unlock
```

### Retrieving Secrets

```bash
# List all items
vaultwarden-cli list

# List only login items
vaultwarden-cli list --type login

# Search for items
vaultwarden-cli list --search github

# Get a specific item (by name or ID)
vaultwarden-cli get "My Login"

# Get item as environment variable exports
vaultwarden-cli get "My Login" --format env
# Output:
# export MY_LOGIN_URI="https://example.com"
# export MY_LOGIN_USERNAME="user@example.com"
# export MY_LOGIN_PASSWORD="secret123"

# Get just the password (useful for piping)
vaultwarden-cli get "My Login" --format value
vaultwarden-cli get "My Login" --password   # shorthand
vaultwarden-cli get "My Login" -p           # short flag

# Get just the username
vaultwarden-cli get "My Login" --format username
vaultwarden-cli get "My Login" --username   # shorthand
vaultwarden-cli get "My Login" -u           # short flag

# Get item by URI instead of name
vaultwarden-cli get-uri github.com
vaultwarden-cli get-uri github.com -p       # just password
vaultwarden-cli get-uri github.com -u       # just username
```

### Using in Scripts

```bash
# Source credentials into environment
eval $(vaultwarden-cli get "AWS Production" --format env)
aws s3 ls

# Pass password to another command
vaultwarden-cli get "Database" --format value | psql -U admin -W

# Use in a script
#!/bin/bash
DB_PASS=$(vaultwarden-cli get "Database" --format value)
mysql -u root -p"$DB_PASS" -e "SELECT 1"
```

### Session Management

```bash
# Check current status
vaultwarden-cli status

# Lock the vault (clears decryption keys)
vaultwarden-cli lock

# Logout completely (clears all saved data)
vaultwarden-cli logout
```

## Output Formats

| Format | Description |
|--------|-------------|
| `json` | Full item details as JSON (default) |
| `env` | Shell export commands for URI, USERNAME, PASSWORD, and custom fields |
| `value` | Just the password, no newline |
| `username` | Just the username, no newline |

## Configuration

Configuration is stored in:
- Linux: `~/.config/vaultwarden-cli/`
- macOS: `~/Library/Application Support/com.vaultwarden.vaultwarden-cli/`
- Windows: `%APPDATA%\vaultwarden\vaultwarden-cli\`

Client secrets are stored securely using the system keyring (libsecret on Linux, Keychain on macOS, Credential Manager on Windows).

## Security

- Master password is never stored; only the derived encryption keys are persisted
- Client secrets are stored in the system keyring, not plain text
- Decryption keys can be cleared at any time with `lock`
- All cryptographic operations use well-audited Rust crates

## Building

Requirements:
- Rust 1.70+
- On Linux: `libdbus-1-dev` and `libsecret-1-dev` for keyring support

```bash
cargo build --release
```

## Tested On

- Arch Linux

## Disclaimer

This project was written with the assistance of AI (Claude). While it has been tested and works, please review the code and use at your own risk. Contributions and bug reports are welcome.

## License

MIT

## Acknowledgments

- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Bitwarden-compatible server
- [Bitwarden](https://bitwarden.com/) - Original password manager
