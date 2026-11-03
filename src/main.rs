use clap::Parser;
use cortex::{
    commands::{account, mcp, pass, vault},
    core::password::PasswordCharset,
    ui::cli::{Cli, Commands},
};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Account { action } => account::run(action),
        Commands::Mcp { action } => mcp::run(action),
        Commands::Vault { action } => vault::run(action),
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
        } => {
            let bits = [
                (uppercase, PasswordCharset::UPPERCASE),
                (lowercase, PasswordCharset::LOWERCASE),
                (digits, PasswordCharset::DIGITS),
                (special, PasswordCharset::SPECIAL),
            ]
            .into_iter()
            .filter(|(enabled, _)| *enabled)
            .fold(0, |bits, (_, flag)| bits | flag);
            pass::execute(length, count, PasswordCharset::from_bits(bits))
        }
    }
}
