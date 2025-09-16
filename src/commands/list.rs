use std::process;

use crate::{
    core::{crypto::Crypto, storage::Storage},
    ui::prompt::UserPrompt,
};

pub struct List;

impl List {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let mut failure = 0;

        let (storage, crypto) = loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break (storage_attempt, crypto);
            } else if failure > 1 {
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        };

        let mut entries = Vec::new();

        for (name, entry) in storage.list_entries()? {
            let description = crypto.decrypt_description(&entry)?;
            entries.push((name, description));
        }

        if entries.is_empty() {
            println!("No entries");
        } else {
            for (name, description) in entries {
                println!();
                println!("Entry: {}", name);
                if let Some(desc) = &description {
                    println!("Description: {}", desc);
                }
            }
        }

        Ok(())
    }
}
