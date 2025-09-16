use crate::{
    core::{crypto::Crypto, storage::Storage},
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Delete;

impl Delete {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let mut failure = 0;

        let storage = loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break storage_attempt;
            } else if failure > 1 {
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        };

        if storage.delete_password(&name)? {
            println!("Deleted '{}'.", name);
        } else {
            println!("Not found: {}", name);
        }

        Ok(())
    }
}
