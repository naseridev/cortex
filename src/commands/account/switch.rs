use super::resolve_existing;
use crate::{security::session::Session, storage::accounts::Accounts};

pub fn execute(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let account_name = resolve_existing(name, "Account name: ")?;

    if Accounts::active()?.as_deref() == Some(account_name.as_str()) {
        println!("Account '{account_name}' is already active.");
        return Ok(());
    }

    Accounts::switch(&account_name)?;
    Session::clear_session()?;

    println!("Switched to account '{account_name}'.");
    Ok(())
}
