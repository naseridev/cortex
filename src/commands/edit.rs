use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password, tags::TagValidator},
    ui::prompt::UserPrompt,
};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Edit;

impl Edit {
    pub fn execute(name: &str, tags: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") || name.trim().is_empty() {
            return Err("Cannot edit system or empty entries".into());
        }

        let (storage, crypto) = Gateway::login()?;

        let entry = storage
            .get_password(name)?
            .ok_or_else(|| format!("Account '{name}' not found."))?;

        let decrypted = crypto.decrypt_entry(&entry)?;
        let password_str = String::from_utf8(decrypted)?;
        let current_password = SecureString::new(password_str);
        let current_desc = crypto.decrypt_description(&entry)?;
        let current_tags = crypto.decrypt_tags(&entry)?;

        let new_password_input =
            UserPrompt::optional_password("New password (Enter to keep current): ")?;

        let new_password = match new_password_input {
            None => SecureString::new(current_password.as_str().to_string()),
            Some(input_pass) => {
                Password::length_check(input_pass.as_str(), MIN_ACCOUNT_PASSWORD_LENGTH)?;
                let confirm_password = UserPrompt::password("Confirm new password: ")?;
                Password::match_check(input_pass.as_str(), confirm_password.as_str())?;
                input_pass
            }
        };

        let description_input =
            UserPrompt::text_with_limit("New description (Enter to keep current): ", 500)?;

        let description = if description_input.is_empty() {
            current_desc.as_deref()
        } else {
            Some(description_input.as_str())
        };

        if let Some(desc) = description {
            Password::in_desc_check(new_password.as_str(), desc)?;
        }

        let tag_list = if let Some(tag_string) = tags {
            let parsed = TagValidator::parse_input(&tag_string);
            let normalized = TagValidator::normalize(&parsed);
            TagValidator::validate(&normalized)?;
            Some(normalized)
        } else if current_tags.is_empty() {
            None
        } else {
            Some(current_tags.clone())
        };

        let current_tags_opt = if current_tags.is_empty() {
            None
        } else {
            Some(&current_tags)
        };

        let no_changes = new_password.as_str() == current_password.as_str()
            && description == current_desc.as_deref()
            && tag_list.as_ref() == current_tags_opt;

        if no_changes {
            println!("No changes made to '{name}'.");
            return Ok(());
        }

        let updated_entry =
            crypto.create_entry(new_password.as_bytes(), description, tag_list.as_deref())?;

        if !storage.edit_password(name, &updated_entry)? {
            return Err(format!("Account '{name}' not found.").into());
        }

        println!("Edited '{name}'.");
        Ok(())
    }
}
