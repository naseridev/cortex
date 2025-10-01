use crate::{modules::gateway::Gateway, utils::security::Security};

pub struct Purge;

impl Purge {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Gateway::login_storage_only()?;

        let warning_message = "This will permanently delete all stored passwords!";
        let purge_confirmation = Security::confirmation(warning_message)?;

        if !purge_confirmation {
            println!("Wrong answer. Destruction cancelled.");
            return Ok(());
        }

        storage.purge_database()?;
        println!("Database purged.");

        Ok(())
    }
}
