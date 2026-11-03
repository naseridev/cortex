use clap::Parser;
use cortex::{
    commands::{
        account, config, create::Create, delete::Delete, dump::Dump, edit::Edit, export::Export,
        find::Find, get::Get, import::Import, list::List, lock::Lock, mcp, pass::Pass,
        restore::Restore, tag,
    },
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
        Commands::Create { name, tags } => Create::execute(&name, tags),
        Commands::Get { name, show } => Get::execute(&name, show),
        Commands::List { show_tags } => List::execute(show_tags),
        Commands::Delete { name } => Delete::execute(&name),
        Commands::Edit { name, tags } => Edit::execute(&name, tags),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Find::execute(&pattern, ignore_case, names_only),
        Commands::Export => Export::execute(),
        Commands::Import { file, overwrite } => Import::execute(&file, overwrite),
        Commands::Dump => Dump::execute(),
        Commands::Restore { file } => Restore::execute(&file),
        Commands::Lock => Lock::execute(),
        Commands::Config { action } => config::run(action),
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
            Pass::execute(length, count, PasswordCharset::from_bits(bits))
        }
        Commands::Tag { action } => tag::run(action),
    }
}
