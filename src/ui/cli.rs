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

    #[command(about = "Export all passwords to plain text file")]
    Export,

    #[command(about = "Reset the master password")]
    Reset,

    #[command(about = "Permanently purge the entire password database")]
    Purge,

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

        #[arg(
            short = 'u',
            long,
            help = "Include uppercase letters",
            default_value = "true"
        )]
        uppercase: bool,

        #[arg(
            short = 'l',
            long,
            help = "Include lowercase letters",
            default_value = "true"
        )]
        lowercase: bool,

        #[arg(short = 'd', long, help = "Include digits", default_value = "true")]
        digits: bool,

        #[arg(
            short = 's',
            long,
            help = "Include special characters",
            default_value = "true"
        )]
        special: bool,

        #[arg(
            short = 'n',
            long,
            help = "Exclude ambiguous characters (0, O, l, 1, etc.)"
        )]
        no_ambiguous: bool,
    },
}
