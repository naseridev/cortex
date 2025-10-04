use crate::{modules::gateway::Gateway, utils::security::Security};

pub struct Purge;

impl Purge {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Gateway::login_storage_only()?;

        let warning_message = "This will permanently delete all stored passwords!";
        Security::confirmation(warning_message)?;

        storage.purge_database()?;
        println!("Database purged.");

        Ok(())
    }
}
