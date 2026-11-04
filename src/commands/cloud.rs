pub mod add;
pub mod default;
pub mod list;
pub mod pull;
pub mod push;
pub mod remove;
pub mod status;
pub mod sync;

use crate::{
    core::{accounts::Accounts, validation::Validation},
    ui::cli::CloudAction,
};

pub fn run(action: CloudAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        CloudAction::Add { provider } => add::execute(provider),
        CloudAction::Sync { remote, account } => sync::execute(remote.as_deref(), account),
        CloudAction::Push {
            remote,
            account,
            force,
        } => push::execute(remote.as_deref(), account, force),
        CloudAction::Pull {
            remote,
            account,
            overwrite,
        } => pull::execute(remote.as_deref(), account, overwrite),
        CloudAction::List => list::execute(),
        CloudAction::Status { remote, account } => status::execute(remote.as_deref(), account),
        CloudAction::Default { name } => default::execute(&name),
        CloudAction::Remove { name } => remove::execute(&name),
    }
}

pub fn resolve_account(provided: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(name) = provided {
        let trimmed = name.trim().to_string();
        Validation::check_account_name(&trimmed)?;
        return Ok(trimmed);
    }

    Accounts::active()?.ok_or_else(|| {
        "No active account found. Specify --account or create one with 'account create'.".into()
    })
}
