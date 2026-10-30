use clap::Parser;
use cortex::{
    commands::{
        config::ConfigCmd, create::Create, delete::Delete, edit::Edit, export::Export, find::Find,
        get::Get, import::Import, init::Init, list::List, lock::Lock, pass::Pass, purge::Purge,
        reset::Reset, tag::Tag,
    },
    modules::{password::PasswordCharset, tags::TagValidator},
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
        Commands::Get { name, clip } => Get::execute(&name, clip),
        Commands::List { show_tags } => List::execute(show_tags),
        Commands::Delete { name } => Delete::execute(&name),
        Commands::Edit { name, tags } => Edit::execute(&name, tags),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Find::execute(&pattern, ignore_case, names_only),
        Commands::Export { template } => Export::execute(template),
        Commands::Import { file, overwrite } => Import::execute(&file, overwrite),
        Commands::Reset => Reset::execute(),
        Commands::Purge => Purge::execute(),
        Commands::Lock => Lock::execute(),
        Commands::Config { action } => match action {
            Some(ConfigAction::SetTimeout { seconds }) => ConfigCmd::set_timeout(seconds),
            Some(ConfigAction::Show) | None => ConfigCmd::show(),
        },
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
        } => {
            let mut bits = 0;
            if uppercase {
                bits |= PasswordCharset::UPPERCASE;
            }
            if lowercase {
                bits |= PasswordCharset::LOWERCASE;
            }
            if digits {
                bits |= PasswordCharset::DIGITS;
            }
            if special {
                bits |= PasswordCharset::SPECIAL;
            }
            Pass::execute(length, count, PasswordCharset::from_bits(bits))
        }
        Commands::Tag { action } => run_tag(action),
    }
}

fn run_tag(action: TagAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        TagAction::List => Tag::list(),
        TagAction::Add { name, tags } => {
            let parsed = TagValidator::parse_input(&tags);
            Tag::add(&name, &parsed)
        }
        TagAction::Remove { name, tags } => {
            let parsed = TagValidator::parse_input(&tags);
            Tag::remove(&name, &parsed)
        }
    }
}
