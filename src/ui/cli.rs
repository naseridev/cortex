use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "Keep your passwords safe",
    version = "4.0.0",
    author = "Nima Naseri <nerdnull@proton.me>"
)]
#[command(
    long_about = "A no-nonsense password manager using Argon2id key derivation and authenticated encryption."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Manage accounts")]
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },

    #[command(about = "Manage Model Context Protocol (MCP) server and agent permissions")]
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },

    #[command(about = "Manage password entries, tags, and the vault session")]
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },

    #[command(about = "Generate strong passwords")]
    Pass {
        #[arg(short = 'l', long, help = "Password length", default_value = "16")]
        length: usize,
        #[arg(
            short = 'c',
            long,
            help = "Number of passwords to generate",
            default_value = "1"
        )]
        count: usize,
        #[arg(short = 'u', long, help = "Include uppercase letters")]
        uppercase: bool,
        #[arg(short = 'w', long, help = "Include lowercase letters")]
        lowercase: bool,
        #[arg(short = 'd', long, help = "Include digits")]
        digits: bool,
        #[arg(short = 's', long, help = "Include special characters")]
        special: bool,
    },

    #[command(about = "Export all passwords to a plaintext CSV file in the current directory")]
    Export,

    #[command(about = "Import passwords from an encrypted export or a CSV export")]
    Import {
        #[arg(help = "Path to an encrypted export or CSV file to import")]
        file: String,
        #[arg(
            short = 'o',
            long = "overwrite",
            help = "Overwrite existing entries with same name"
        )]
        overwrite: bool,
    },

    #[command(about = "Write an encrypted dump of the database to the current directory")]
    Dump,

    #[command(about = "Restore the database from a dump file, replacing its contents")]
    Restore {
        #[arg(help = "Path to a dump file created by the dump command")]
        file: String,
    },
}

#[derive(Subcommand)]
pub enum VaultAction {
    #[command(about = "Create a new password entry")]
    Create {
        #[arg(help = "Name/identifier for the password entry")]
        name: String,
        #[arg(short = 't', long = "tags", help = "Comma-separated tags")]
        tags: Option<String>,
    },

    #[command(about = "Retrieve a password entry")]
    Get {
        #[arg(help = "Name of the password entry to retrieve")]
        name: String,
        #[arg(
            long,
            help = "Print the password instead of copying it to the clipboard"
        )]
        show: bool,
    },

    #[command(about = "Edit password and description for existing entry")]
    Edit {
        #[arg(help = "Name of the password entry to edit")]
        name: String,
        #[arg(short = 't', long = "tags", help = "Replace tags (comma-separated)")]
        tags: Option<String>,
    },

    #[command(about = "Delete a password entry")]
    Delete {
        #[arg(help = "Name of the password entry to delete")]
        name: String,
    },

    #[command(about = "List all stored password entries")]
    List {
        #[arg(short = 't', long = "tags", help = "Show tags for each entry")]
        show_tags: bool,
    },

    #[command(about = "Search password entries by name, description, or tags")]
    Find {
        #[arg(help = "Search pattern (supports regex)")]
        pattern: String,
        #[arg(short, long, help = "Case insensitive search")]
        ignore_case: bool,
        #[arg(short, long, help = "Search only in names (not descriptions or tags)")]
        names_only: bool,
    },

    #[command(about = "Manage tags for password entries")]
    Tag {
        #[command(subcommand)]
        action: TagAction,
    },

    #[command(about = "Clear authentication session and require re-login")]
    Lock,
}

#[derive(Subcommand)]
pub enum AccountAction {
    #[command(about = "Create a new account")]
    Create {
        #[arg(help = "Name for the new account")]
        name: Option<String>,
    },

    #[command(about = "List all existing accounts")]
    List,

    #[command(about = "Edit an existing account name")]
    Edit {
        #[arg(help = "Current name of the account")]
        name: Option<String>,
        #[arg(help = "New name for the account")]
        new_name: Option<String>,
    },

    #[command(about = "Delete an existing account")]
    Delete {
        #[arg(help = "Name of the account to delete")]
        name: Option<String>,
    },

    #[command(about = "Switch between accounts")]
    Switch {
        #[arg(help = "Name of the account to switch to")]
        name: Option<String>,
    },

    #[command(about = "Reset the master password of an account")]
    Reset {
        #[arg(help = "Name of the account whose master password to reset")]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum McpAction {
    #[command(about = "Initialize MCP server configuration and agent workspace")]
    Init,

    #[command(about = "Start the MCP JSON-RPC server over stdio")]
    Serve,

    #[command(
        about = "Show or set 3-digit binary MCP permission (hundreds: account create, tens: write/delete, ones: read)"
    )]
    Permission {
        #[arg(help = "3-digit binary mode from 000 to 111 (omit to view current permission)")]
        mode: Option<String>,
    },

    #[command(about = "Enable or disable agent account isolation (on/off)")]
    Sandbox {
        #[arg(help = "Sandbox state: 'on' or 'off' (omit to view current state)")]
        state: Option<String>,
    },

    #[command(about = "Show current MCP status, permission, sandbox state, and agent accounts")]
    Status,

    #[command(about = "Remove MCP configuration")]
    Remove {
        #[arg(
            long = "purge-accounts",
            help = "Also permanently delete all [agent] accounts"
        )]
        purge_accounts: bool,
    },
}

#[derive(Subcommand)]
pub enum TagAction {
    #[command(about = "List all tags with usage counts")]
    List,

    #[command(about = "Add tags to an entry")]
    Add {
        #[arg(help = "Entry name")]
        name: String,
        #[arg(help = "Comma-separated tags to add")]
        tags: String,
    },

    #[command(about = "Remove tags from an entry")]
    Remove {
        #[arg(help = "Entry name")]
        name: String,
        #[arg(help = "Comma-separated tags to remove")]
        tags: String,
    },
}
