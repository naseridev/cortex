use super::{resolve_existing, resolve_name};
use crate::core::{accounts::Accounts, gateway::Gateway, validation::Validation};

pub fn execute(
    name: Option<String>,
    new_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_name = resolve_existing(name, "Account name: ")?;

    let (storage, _) = Gateway::login_account(&current_name)?;
    drop(storage);

    let updated_name = resolve_name(new_name, "New account name: ")?;
    Validation::check_account_name(&updated_name)?;

    if updated_name == current_name {
        println!("No changes made to '{current_name}'.");
        return Ok(());
    }

    if Accounts::exists(&updated_name)? {
        return Err(
            format!("Account '{updated_name}' already exists. Choose a different name.").into(),
        );
    }

    Accounts::rename(&current_name, &updated_name)?;
    println!("Renamed account '{current_name}' to '{updated_name}'.");

    Ok(())
}
