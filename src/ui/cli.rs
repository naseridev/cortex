use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "Keep your passwords safe",
    version = "3.0.0",
    author = "Nima Naseri <nerdnull@proton.me>"
)]
#[command(long_about = "A no-nonsense password manager using hardware-backed key derivation.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Initialize a new password database with master password")]
    Init,

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
            short = 'c',
            long = "clip",
            help = "Copy password to clipboard for specified seconds (default: 43)",
            value_name = "SECONDS"
        )]
        clip: Option<Option<u64>>,
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

    #[command(about = "Export all passwords to JSON file")]
    Export {
        #[arg(
            short = 't',
            long = "template",
            help = "Export a sample template file instead of actual passwords"
        )]
        template: bool,
    },

    #[command(about = "Import passwords from JSON file")]
    Import {
        #[arg(help = "Path to JSON file to import")]
        file: String,
        #[arg(
            short = 'o',
            long = "overwrite",
            help = "Overwrite existing entries with same name"
        )]
        overwrite: bool,
    },

    #[command(about = "Reset the master password")]
    Reset,

    #[command(about = "Manage configuration settings")]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    #[command(about = "Clear authentication session and require re-login")]
    Lock,

    #[command(about = "Permanently purge the entire password database")]
    Purge,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    #[command(about = "Show current configuration")]
    Show,

    #[command(about = "Set session timeout in seconds")]
    SetTimeout {
        #[arg(help = "Timeout in seconds (60-86400)")]
        seconds: u64,
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
