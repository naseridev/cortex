use crate::{
    core::{
        crypto::{Crypto, get_test_data},
        storage::Storage,
    },
    modules::validation::Validation,
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Init;

impl Init {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        if Storage::get_db_path().exists() {
            eprintln!("Database exists. Use 'reset' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;

        if let Err(msg) = Validation::password_security(master_password.as_str()) {
            eprintln!("Error: {}", msg);
            process::exit(1);
        }

        let confirm_password = UserPrompt::password("Confirm password: ")?;

        if master_password.as_str() != confirm_password.as_str() {
            return Err("Password mismatch".into());
        }

        let entry = Crypto::new(&master_password).create_entry(get_test_data(), None)?;
        let _ = Storage::new()?.init_db(&entry);

        println!("Initialized.");

        Ok(())
    }
}
