use super::resolve_name;
use crate::{
    core::{accounts::Accounts, validation::Validation},
    modules::session::Session,
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

    if Accounts::active()?.as_deref() == Some(account_name.as_str()) {
        println!("Account '{account_name}' is already active.");
        return Ok(());
    }

    Accounts::switch(&account_name)?;
    Session::clear_session()?;

    println!("Switched to account '{account_name}'.");
    Ok(())
}
