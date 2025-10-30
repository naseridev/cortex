use crate::core::types::SecureString;
use std::io::{self, Write};

pub struct UserPrompt;

impl UserPrompt {
    pub fn password(prompt: &str) -> Result<SecureString, Box<dyn std::error::Error>> {
        let password = rpassword::prompt_password(prompt)?;

        if password.is_empty() {
            return Err("Empty password not allowed".into());
        }

        if password.len() > 128 {
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(SecureString::new(password))
    }

    pub fn text(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim().to_string();

        if trimmed.len() > 128 {
            return Err("Input too long (max 128 chars)".into());
        }

        Ok(trimmed)
    }
}
