use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password, tags::TagValidator},
    ui::prompt::UserPrompt,
};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Edit;

impl Edit {
    pub fn new(name: String, tags: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Cannot edit system entries".into());
        }

        let (storage, crypto) = Gateway::login()?;

        let current_entry = match storage.get_password(&name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(&entry)?;
                let password_str = String::from_utf8(decrypted)?;
                let password = SecureString::new(password_str);
                let description = crypto.decrypt_description(&entry)?;
                let existing_tags = crypto.decrypt_tags(&entry)?;
                Some((password, description, existing_tags))
            }
            None => None,
        };

        let new_password_input = UserPrompt::text("New password (Enter to keep current): ")?;
        let new_password = if new_password_input.is_empty() {
            match &current_entry {
                Some((password, _, _)) => password.as_str().to_string(),
                None => return Err("No current password found".into()),
            }
        } else {
            Password::length_check(&new_password_input, MIN_ACCOUNT_PASSWORD_LENGTH)?;
            let confirm_password = UserPrompt::text("Confirm new password: ")?;

            Password::match_check(new_password_input.as_str(), confirm_password.as_str())?;
            new_password_input
        };

        let description_input = UserPrompt::text("New description (Enter to keep current): ")?;

        if description_input.len() > 500 {
            return Err("Description too long (max 500 chars)".into());
        }

        let description = if description_input.is_empty() {
            match &current_entry {
                Some((_, desc, _)) => desc.as_deref(),
                None => None,
            }
        } else {
            Password::in_desc_check(&new_password, &description_input)?;
            Some(description_input.as_str())
        };

        let tag_list = if let Some(tag_string) = tags {
            let parsed = TagValidator::parse_input(&tag_string);
            let normalized = TagValidator::normalize(&parsed);
            TagValidator::validate(&normalized)?;
            Some(normalized)
        } else {
            match &current_entry {
                Some((_, _, existing_tags)) => Some(existing_tags.clone()),
                None => None,
            }
        };

        let no_changes = match &current_entry {
            Some((current_password, current_desc, current_tags)) => {
                new_password == current_password.as_str()
                    && description == current_desc.as_deref()
                    && tag_list.as_ref() == Some(current_tags)
            }
            None => false,
        };

        if no_changes {
            println!("No changes made to '{}'.", name);
            return Ok(());
        }

        let secure_password = SecureString::new(new_password);
        let entry =
            crypto.create_entry(secure_password.as_bytes(), description, tag_list.as_deref())?;

        if storage.edit_password(&name, &entry)? {
            println!("Edited for '{}'.", name);
        }

        Ok(())
    }
}
