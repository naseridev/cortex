use clap::Parser;
use cortex::{
    commands::{
        config::ConfigCmd, create::Create, delete::Delete, dump::Dump, edit::Edit, export::Export,
        find::Find, get::Get, import::Import, init::Init, list::List, lock::Lock, pass::Pass,
        purge::Purge, reset::Reset, restore::Restore, tag::Tag,
    },
    core::{password::PasswordCharset, tags::TagValidator},
    ui::cli::{Cli, Commands, ConfigAction, TagAction},
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
        Commands::Init => Init::execute(),
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
        Commands::Reset => Reset::execute(),
        Commands::Dump => Dump::execute(),
        Commands::Restore { file } => Restore::execute(&file),
        Commands::Purge => Purge::execute(),
        Commands::Lock => Lock::execute(),
        Commands::Config { action } => run_config(action),
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
        } => {
            let charset = charset_from_flags(uppercase, lowercase, digits, special);
            Pass::execute(length, count, charset)
        }
        Commands::Tag { action } => run_tag(action),
    }
}

fn run_config(action: Option<ConfigAction>) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        Some(ConfigAction::SetTimeout { seconds }) => ConfigCmd::set_timeout(seconds),
        Some(ConfigAction::Show) | None => ConfigCmd::show(),
    }
}

fn run_tag(action: TagAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        TagAction::List => Tag::list(),
        TagAction::Add { name, tags } => Tag::add(&name, &TagValidator::parse_input(&tags)),
        TagAction::Remove { name, tags } => Tag::remove(&name, &TagValidator::parse_input(&tags)),
    }
}

fn charset_from_flags(
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    special: bool,
) -> PasswordCharset {
    let bits = [
        (uppercase, PasswordCharset::UPPERCASE),
        (lowercase, PasswordCharset::LOWERCASE),
        (digits, PasswordCharset::DIGITS),
        (special, PasswordCharset::SPECIAL),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .fold(0, |bits, (_, flag)| bits | flag);

    PasswordCharset::from_bits(bits)
}
