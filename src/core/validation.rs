use crate::core::{limits::MAX_NAME_BYTES, storage::Storage};

pub struct Validation;

impl Validation {
    pub fn storage_probe(
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = Storage::database_exists()?;

        if exists != should_exist {
            if should_exist && Storage::legacy_database_present()? {
                return Err(Storage::legacy_database_message().into());
            }
            return Err(error_message.into());
        }

        Ok(())
    }

    pub fn account_exists_probe(
        storage: &Storage,
        name: &str,
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = storage.entry_exists(name)?;

        if exists != should_exist {
            return Err(error_message.into());
        }

        Ok(())
    }

    pub fn check_account_name(name: &str) -> Result<(), String> {
        if name.trim().is_empty() || name.starts_with("__") || name.len() > MAX_NAME_BYTES {
            return Err("Invalid account name".to_string());
        }
        if name.chars().any(is_unsafe_char) {
            return Err(
                "Account name contains a control or hidden formatting character".to_string(),
            );
        }
        Ok(())
    }

    pub fn check_description_text(description: &str) -> Result<(), String> {
        if description.chars().any(is_unsafe_char) {
            return Err(
                "Description contains a control or hidden formatting character".to_string(),
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn printable(text: &str) -> String {
        let mut output = String::with_capacity(text.len());
        for ch in text.chars() {
            if is_unsafe_char(ch) {
                output.extend(ch.escape_default());
            } else {
                output.push(ch);
            }
        }
        output
    }
}

fn is_unsafe_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}
