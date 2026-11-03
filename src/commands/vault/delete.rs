use crate::core::validation::Validation;
use crate::modules::gateway::Gateway;

pub fn execute(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Validation::is_reserved_or_blank(name) {
        return Err("Cannot delete system or empty entries".into());
    }

    let storage = Gateway::login_storage_only()?;
    let not_found = format!("Account '{name}' not found.");

    Validation::account_exists_probe(&storage, name, true, &not_found)?;

    if !storage.delete_password(name)? {
        return Err(not_found.into());
    }

    println!("Deleted '{name}'.");
    Ok(())
}
