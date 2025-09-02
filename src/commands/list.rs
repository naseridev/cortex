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

        let master_password = UserPrompt::password("Master password: ")?;

        let crypto = Crypto::new(&master_password);
        let storage = Storage::new()?;

        let result = match storage.get_init_marker()? {
            Some(entry) => crypto.verify_test_data(&entry),
            None => false,
        };

        if !result {
            return Err("Authentication failed".into());
        }

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
