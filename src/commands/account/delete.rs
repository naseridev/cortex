use super::resolve_existing;
use crate::{
    core::{accounts::Accounts, gateway::Gateway, session::Session},
    ui::confirm::Confirmation,
};

pub fn execute(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let account_name = resolve_existing(name, "Account name: ")?;

    let (storage, _) = Gateway::login_account_for_recovery(&account_name)?;
    drop(storage);

    let warning_message = format!(
        "This will permanently delete account '{account_name}' and all its stored passwords!"
    );

    Confirmation::require(&warning_message)?;
    let was_active = Accounts::delete(&account_name)?;

    if was_active {
        Session::clear_session()?;
    }

    println!("Deleted account '{account_name}'.");
    Ok(())
}
