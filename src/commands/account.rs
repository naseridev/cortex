pub mod create;
pub mod delete;
pub mod dump;
pub mod edit;
pub mod export;
pub mod import;
pub mod list;
pub mod reset;
pub mod restore;
pub mod switch;

use crate::{
    domain::validation::Validation,
    storage::accounts::{Accounts, NO_ACCOUNTS},
    ui::{cli::AccountAction, prompt::UserPrompt},
};

pub fn run(action: AccountAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AccountAction::Create { name } => create::execute(name),
        AccountAction::List => list::execute(),
        AccountAction::Edit { name, new_name } => edit::execute(name, new_name),
        AccountAction::Delete { name } => delete::execute(name),
        AccountAction::Switch { name } => switch::execute(name),
        AccountAction::Reset { name } => reset::execute(name),
        AccountAction::Export => export::execute(),
        AccountAction::Import { file, overwrite } => import::execute(&file, overwrite),
        AccountAction::Dump => dump::execute(),
        AccountAction::Restore { file } => restore::execute(&file),
    }
}

pub fn resolve_name(
    provided: Option<String>,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match provided {
        Some(name) => Ok(name.trim().to_string()),
        None => UserPrompt::text(prompt),
    }
}

pub fn resolve_existing(
    provided: Option<String>,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let (accounts, _) = Accounts::list()?;
    if accounts.is_empty() {
        return Err(NO_ACCOUNTS.into());
    }

    let account_name = resolve_name(provided, prompt)?;
    Validation::check_account_name(&account_name)?;

    if !accounts.contains(&account_name) || !Accounts::db_file_exists(&account_name)? {
        return Err(format!("Account '{account_name}' not found.").into());
    }

    Ok(account_name)
}
