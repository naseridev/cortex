use super::resolve_name;
use crate::{
    core::{accounts::Accounts, validation::Validation},
    modules::{gateway::Gateway, security::Security, session::Session},
};

pub fn execute(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (accounts, _) = Accounts::list()?;
    if accounts.is_empty() {
        return Err("No accounts found. Create one with 'account create'.".into());
    }

    let account_name = resolve_name(name, "Account name: ")?;
    Validation::check_account_name(&account_name)?;

    if !Accounts::exists(&account_name)? {
        return Err(format!("Account '{account_name}' not found.").into());
    }

    let (storage, _) = Gateway::login_account_for_recovery(&account_name)?;
    drop(storage);

    let warning_message = format!(
        "This will permanently delete account '{account_name}' and all its stored passwords!"
    );

    Security::confirmation(&warning_message)?;
    let was_active = Accounts::delete(&account_name)?;

    if was_active {
        Session::clear_session()?;
    }

    println!("Deleted account '{account_name}'.");
    Ok(())
}
