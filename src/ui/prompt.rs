use crate::core::limits::MAX_INPUT_LINE_BYTES;
use std::io::{self, BufRead, Read, Write};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSWORD_BYTES: usize = 128;
const DEFAULT_TEXT_LIMIT: usize = 128;

pub struct UserPrompt;

impl UserPrompt {
    pub fn password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        match Self::optional_password(prompt)? {
            Some(password) => Ok(password),
            None => Err("Empty password not allowed".into()),
        }
    }

    pub fn visible_password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        print!("{prompt}");
        io::stdout().flush()?;

        let raw = Self::read_bounded_line()?;
        let mut secret = Zeroizing::new(String::from_utf8(raw).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "Input is not valid UTF-8"
        })?);

        while secret.ends_with(['\n', '\r']) {
            secret.pop();
        }

        if secret.is_empty() {
            return Err("Empty password not allowed".into());
        }

        if secret.len() > MAX_PASSWORD_BYTES {
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(secret)
    }

    pub fn optional_password(
        prompt: &str,
    ) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
        let secret = Zeroizing::new(rpassword::prompt_password(prompt)?);

        if secret.is_empty() {
            return Ok(None);
        }

        if secret.len() > MAX_PASSWORD_BYTES {
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(Some(secret))
    }

    pub fn text(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        Self::text_with_limit(prompt, DEFAULT_TEXT_LIMIT)
    }

    pub fn text_with_limit(
        prompt: &str,
        max_len: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        print!("{prompt}");
        io::stdout().flush()?;

        let raw = Self::read_bounded_line()?;
        let mut text = String::from_utf8(raw).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "Input is not valid UTF-8"
        })?;

        let trimmed = text.trim().to_string();
        text.zeroize();

        if trimmed.len() > max_len {
            return Err(format!("Input too long (max {max_len} chars)").into());
        }

        Ok(trimmed)
    }

    fn read_bounded_line() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut raw = Vec::with_capacity(MAX_INPUT_LINE_BYTES);
        let limit = MAX_INPUT_LINE_BYTES as u64 + 1;
        let read = io::stdin().lock().take(limit).read_until(b'\n', &mut raw)?;

        if read > MAX_INPUT_LINE_BYTES {
            raw.zeroize();
            return Err("Input line is too long".into());
        }

        Ok(raw)
    }
}
