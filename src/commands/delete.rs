use crate::modules::{gateway::Gateway, validation::Validation};

pub struct Delete;

impl Delete {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Cannot delete system entries".into());
        }

        let storage = Gateway::login_storage_only()?;

        Validation::account_exists_probe(
            &storage,
            &name,
            true,
            &format!("Account '{}' not found.", name),
        )?;

        storage.delete_password(&name)?;
        println!("Deleted '{}'.", name);

        Ok(())
    }
}
