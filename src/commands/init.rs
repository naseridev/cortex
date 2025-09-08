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

        let master_password = loop {
            let password = UserPrompt::password("Master password: ")?;

            match Validation::password_security(password.as_str()) {
                Ok(_) => {
                    break password;
                }
                Err(msg) => {
                    eprintln!("Error: {}", msg);
                }
            }
        };

        loop {
            let password = UserPrompt::password("Confirm password: ")?;

            if master_password.as_str() == password.as_str() {
                break
            }

            eprintln!("Password mismatch");
        };

        let entry = Crypto::new(&master_password).create_entry(get_test_data(), None)?;
        let _ = Storage::new()?.init_db(&entry);

        println!("Initialized.");

        Ok(())
    }
}
