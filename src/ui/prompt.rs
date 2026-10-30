use crate::core::types::SecureString;
use std::io::{self, Write};
use zeroize::Zeroize;

pub struct UserPrompt;

impl UserPrompt {
    pub fn password(prompt: &str) -> Result<SecureString, Box<dyn std::error::Error>> {
        let mut password = rpassword::prompt_password(prompt)?;

        if password.is_empty() {
            return Err("Empty password not allowed".into());
        }

        if password.len() > 128 {
            password.zeroize();
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(SecureString::new(password))
    }

    pub fn optional_password(
        prompt: &str,
    ) -> Result<Option<SecureString>, Box<dyn std::error::Error>> {
        let mut password = rpassword::prompt_password(prompt)?;

        if password.is_empty() {
            return Ok(None);
        }

        if password.len() > 128 {
            password.zeroize();
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(Some(SecureString::new(password)))
    }

    pub fn text(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        Self::text_with_limit(prompt, 128)
    }

    pub fn text_with_limit(
        prompt: &str,
        max_len: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim().to_string();
        input.zeroize();

        if trimmed.len() > max_len {
            return Err(format!("Input too long (max {} chars)", max_len).into());
        }

        Ok(trimmed)
    }
}
