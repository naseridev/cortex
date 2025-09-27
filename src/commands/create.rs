use crate::{
    core::{crypto::Crypto, storage::Storage, types::SecureString},
    modules::{password::Password, validation::Validation},
    ui::prompt::UserPrompt,
};
use std::process;

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Create;

impl Create {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_existence_probe()?;

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

        if storage.db.get(&name)?.is_some() {
            eprintln!(
                "Error: Account '{}' already exists. Use 'edit' to update or choose a different name.",
                name
            );
            process::exit(1);
        }

        let password = UserPrompt::text("Password to store: ")?;

        if password.len() < MIN_ACCOUNT_PASSWORD_LENGTH {
            return Err(format!(
                "Password must be at least {} characters",
                MIN_ACCOUNT_PASSWORD_LENGTH
            )
            .into());
        }

        let confirm_password = UserPrompt::text("Confirm password: ")?;

        if password.as_str() != confirm_password.as_str() {
            return Err("Password mismatch".into());
        }

        let description_input = UserPrompt::text("Description (optional): ")?;
        let description = if description_input.is_empty() {
            None
        } else if Password::in_desc_found(password.as_str(), &description_input) {
            return Err("Description cannot contain the password or parts of it.".into());
        } else {
            Some(description_input.as_str())
        };

        let entry = crypto.create_entry(&SecureString::new(password).as_bytes(), description)?;

        if storage.create_password(&name, &entry)? {
            println!("Created '{}'.", name);
        }

        Ok(())
    }
}
