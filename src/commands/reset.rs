use crate::{
    core::{
        crypto::{Crypto, get_test_data},
        storage::Storage,
        types::SecureString,
    },
    modules::validation::Validation,
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Reset;

impl Reset {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let (storage, crypto) = loop {
            let old_password = UserPrompt::password("Current master password: ")?;
            let crypto = Crypto::new(&old_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break (storage_attempt, crypto);
            } else {
                eprintln!("Authentication failed. Please try again.");
            }
        };

        let new_password = loop {
            let password = UserPrompt::password("New master password: ")?;

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
            let password = UserPrompt::password("Confirm new password: ")?;

            if new_password.as_str() == password.as_str() {
                break
            }

            eprintln!("Password mismatch");
        };

        let entries = storage.get_all_entries()?;
        let mut decrypted_entries = Vec::new();

        for (name, entry) in &entries {
            let decrypted = crypto.decrypt_entry(entry)?;
            let password = String::from_utf8(decrypted)?;
            let description = crypto.decrypt_description(entry)?;
            decrypted_entries.push((name.clone(), SecureString::new(password), description));
        }

        for (name, password, description) in &decrypted_entries {
            let new_entry = Crypto::encrypt_with_new_key(
                &new_password,
                password.as_bytes(),
                description.as_deref(),
            )?;
            storage.update_entry(name, &new_entry)?;
        }

        let test_entry = Crypto::encrypt_with_new_key(&new_password, get_test_data(), None)?;
        storage.update_entry("__init__", &test_entry)?;
        storage.flush()?;

        println!("Master password reset.");

        Ok(())
    }
}
