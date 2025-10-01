use crate::modules::{gateway::Gateway, validation::Validation};

pub struct Delete;

impl Delete {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
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