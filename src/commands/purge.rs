use crate::{
    core::config::Config,
    modules::{gateway::Gateway, session::Session},
    utils::security::Security,
};

pub struct Purge;

impl Purge {
    pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Gateway::login_storage_only()?;

        let warning_message = "This will permanently delete all stored passwords!";
        Security::confirmation(warning_message)?;

        storage.purge_database()?;
        Session::clear_session()?;
        Config::clear_cache();

        println!("Database purged.");

        Ok(())
    }
}
