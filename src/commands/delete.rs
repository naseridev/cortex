use crate::modules::{gateway::Gateway, validation::Validation};

pub struct Delete;

impl Delete {
    pub fn execute(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") || name.trim().is_empty() {
            return Err("Cannot delete system or empty entries".into());
        }

        let storage = Gateway::login_storage_only()?;

        Validation::account_exists_probe(
            &storage,
            name,
            true,
            &format!("Account '{name}' not found."),
        )?;

        storage.delete_password(name)?;
        println!("Deleted '{name}'.");

        Ok(())
    }
}
