use crate::{modules::gateway::Gateway, utils::confirmation::Confirmation};

pub struct Purge;

impl Purge {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Gateway::login_storage_only()?;

        let warning_message = "This will permanently delete all stored passwords!";
        let purge_confirmation = Confirmation::require_math_puzzle(warning_message)?;

        if !purge_confirmation {
            println!("Wrong answer. Destruction cancelled.");
            return Ok(());
        }

        storage.purge_database()?;
        println!("Database purged.");

        Ok(())
    }
}
