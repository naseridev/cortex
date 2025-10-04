use crate::{
    core::{
        crypto::{Crypto, get_test_data},
        storage::Storage,
    },
    modules::{password::Password, validation::Validation},
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Init;

impl Init {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_probe(
            false,
            "Database already exists. Use a different path or remove existing database.",
        )?;

        let master_password = UserPrompt::password("Master password: ")?;

        if let Err(msg) = Password::security_check(master_password.as_str()) {
            eprintln!("Error: {}", msg);
            process::exit(1);
        }

        let confirm_password = UserPrompt::password("Confirm password: ")?;

        Password::match_check(master_password.as_str(), confirm_password.as_str())?;

        let entry = Crypto::new(&master_password).create_entry(get_test_data(), None)?;
        let _ = Storage::new()?.init_db(&entry);

        println!("Initialized.");

        Ok(())
    }
}
