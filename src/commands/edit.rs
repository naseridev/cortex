use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Edit;

impl Edit {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let current_entry = match storage.get_password(&name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(&entry)?;
                let password = String::from_utf8(decrypted)?;
                let description = crypto.decrypt_description(&entry)?;
                Some((SecureString::new(password), description))
            }
            None => None,
        };

        let new_password_input = UserPrompt::text("New password (Enter to keep current): ")?;
        let new_password = if new_password_input.is_empty() {
            match &current_entry {
                Some((password, _)) => password.as_str().to_string(),
                None => return Err("No current password found".into()),
            }
        } else {
            if new_password_input.len() < MIN_ACCOUNT_PASSWORD_LENGTH {
                return Err(format!(
                    "Password must be at least {} characters",
                    MIN_ACCOUNT_PASSWORD_LENGTH
                )
                .into());
            }

            let confirm_password = UserPrompt::text("Confirm new password: ")?;
            if new_password_input != confirm_password {
                return Err("Password mismatch".into());
            }

            new_password_input
        };

        let description_input = UserPrompt::text("New description (Enter to keep current): ")?;
        let description = if description_input.is_empty() {
            match &current_entry {
                Some((_, desc)) => desc.as_deref(),
                None => None,
            }
        } else {
            if Password::in_desc_found(&new_password, &description_input) {
                return Err("Description cannot contain the password or parts of it.".into());
            }

            Some(description_input.as_str())
        };

        let no_changes = match &current_entry {
            Some((current_password, current_desc)) => {
                new_password == current_password.as_str() && description == current_desc.as_deref()
            }
            None => false,
        };

        if no_changes {
            println!("No changes made to '{}'.", name);
            return Ok(());
        }

        let entry = crypto.create_entry(new_password.as_bytes(), description)?;

        if storage.edit_password(&name, &entry)? {
            println!("Edited for '{}'.", name);
        }

        Ok(())
    }
}
