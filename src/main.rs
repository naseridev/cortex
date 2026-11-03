use clap::Parser;
use cortex::{
    commands::{
        account::Account, config::ConfigCmd, create::Create, delete::Delete, dump::Dump,
        edit::Edit, export::Export, find::Find, get::Get, import::Import, list::List, lock::Lock,
        mcp::Mcp, pass::Pass, restore::Restore, tag::Tag,
    },
    core::{password::PasswordCharset, tags::TagValidator},
    ui::cli::{AccountAction, Cli, Commands, ConfigAction, McpAction, TagAction},
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
        Commands::Account { action } => run_account(action),
        Commands::Mcp { action } => run_mcp(action),
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
        Commands::Tag { action } => run_tag(action),
    }
}

fn run_account(action: AccountAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AccountAction::Create { name } => Account::create(name),
        AccountAction::List => Account::list(),
        AccountAction::Edit { name, new_name } => Account::edit(name, new_name),
        AccountAction::Delete { name } => Account::delete(name),
        AccountAction::Switch { name } => Account::switch(name),
        AccountAction::Reset { name } => Account::reset(name),
    }
}

fn run_mcp(action: McpAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        McpAction::Init => Mcp::init(),
        McpAction::Serve => Mcp::serve(),
        McpAction::Permission { mode } => Mcp::permission(mode),
        McpAction::Sandbox { state } => Mcp::sandbox(state),
        McpAction::Status => Mcp::status(),
        McpAction::Remove { purge_accounts } => Mcp::remove(purge_accounts),
    }
}

fn run_tag(action: TagAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        TagAction::List => Tag::list(),
        TagAction::Add { name, tags } => Tag::add(&name, &TagValidator::parse_input(&tags)),
        TagAction::Remove { name, tags } => Tag::remove(&name, &TagValidator::parse_input(&tags)),
    }
}
