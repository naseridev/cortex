use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "Keep your passwords safe",
    version = "2.0.0",
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

    #[command(about = "List all stored password entries")]
    List,

    #[command(about = "Delete a password entry")]
    Delete {
        #[arg(help = "Name of the password entry to delete")]
        name: String,
    },

    #[command(about = "Edit password and description for existing entry")]
    Edit {
        #[arg(help = "Name of the password entry to edit")]
        name: String,
    },

    #[command(about = "Search password entries by name or description")]
    Find {
        #[arg(help = "Search pattern (supports regex)")]
        pattern: String,
        #[arg(short, long, help = "Case insensitive search")]
        ignore_case: bool,
        #[arg(short, long, help = "Search only in names (not descriptions)")]
        names_only: bool,
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

    #[command(about = "Permanently purge the entire password database")]
    Purge,

    #[command(about = "Clear authentication session and require re-login")]
    Lock,

    #[command(about = "Manage configuration settings")]
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    #[command(about = "Generate strong passwords")]
    Pass {
        #[arg(short = 'e', long, help = "Password length", default_value = "16")]
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
        #[arg(short = 'l', long, help = "Include lowercase letters")]
        lowercase: bool,
        #[arg(short = 'd', long, help = "Include digits")]
        digits: bool,
        #[arg(short = 's', long, help = "Include special characters")]
        special: bool,
    },
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
