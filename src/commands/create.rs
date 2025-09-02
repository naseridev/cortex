use crate::{
    core::{crypto::Crypto, storage::Storage, types::SecureString},
    modules::validation::Validation,
    ui::prompt::UserPrompt,
};
use std::process;

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Create;

impl Create {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
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
        } else if Validation::password_in_desc_found(password.as_str(), &description_input) {
            eprintln!("Error: Description cannot contain the password or parts of it.");
            process::exit(1);
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
