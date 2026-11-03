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

use crate::ui::{cli::AccountAction, prompt::UserPrompt};

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
