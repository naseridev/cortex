use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};
use std::process;

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Create;

impl Create {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

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
