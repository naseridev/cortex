use std::io::{self, BufRead, Read, Write};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSWORD_BYTES: usize = 256;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 1024;

pub struct UserPrompt;

impl UserPrompt {
    pub fn password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        match Self::optional_password(prompt)? {
            Some(password) => Ok(password),
            None => Err("Empty password not allowed".into()),
        }
    }

    pub fn token(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        match Self::optional_token(prompt)? {
            Some(token) => Ok(token),
            None => Err("Empty token not allowed".into()),
        }
    }

    pub fn visible_password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        print!("{prompt}");
        io::stdout().flush()?;

        let raw = Self::read_bounded_line()?;
        let mut text = String::from_utf8(raw).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "Input is not valid UTF-8"
        })?;

        while text.ends_with(['\n', '\r']) {
            text.pop();
        }

        let password = Zeroizing::new(text);
        if password.is_empty() {
            return Err("Empty password not allowed".into());
        }

        if password.len() > MAX_PASSWORD_BYTES {
            return Err(format!("Password too long (max {MAX_PASSWORD_BYTES} bytes).").into());
        }

        Ok(password)
    }

    pub fn optional_password(
        prompt: &str,
    ) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
        let password = rpassword::prompt_password(prompt)?;
        let trimmed = password.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            return Ok(None);
        }

        if trimmed.len() > MAX_PASSWORD_BYTES {
            return Err(format!("Password too long (max {MAX_PASSWORD_BYTES} bytes).").into());
        }

        let secret = Zeroizing::new(trimmed.to_string());
        Ok(Some(secret))
    }

    pub fn optional_token(
        prompt: &str,
    ) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
        print!("{prompt}");
        io::stdout().flush()?;

        let raw = Self::read_bounded_line()?;
        let mut text = String::from_utf8(raw).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "Input is not valid UTF-8"
        })?;

        while text.ends_with(['\n', '\r']) {
            text.pop();
        }

        let token = Zeroizing::new(text.trim().to_string());
        text.zeroize();

        if token.is_empty() {
            return Ok(None);
        }

        if token.len() > MAX_TOKEN_BYTES {
            return Err(format!("Token too long (max {MAX_TOKEN_BYTES} bytes).").into());
        }

        if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("Token contains invalid characters.".into());
        }

        Ok(Some(token))
    }

    pub fn text(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        Self::text_with_limit(prompt, MAX_TEXT_BYTES)
    }

    pub fn text_with_limit(
        prompt: &str,
        max_bytes: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        print!("{prompt}");
        io::stdout().flush()?;

        let raw = Self::read_bounded_line()?;
        let mut line = String::from_utf8(raw).map_err(|_| "Input is not valid UTF-8")?;

        while line.ends_with(['\n', '\r']) {
            line.pop();
        }

        let trimmed = line.trim().to_string();
        if trimmed.len() > max_bytes {
            return Err(format!("Input too long (max {max_bytes} bytes).").into());
        }

        Ok(trimmed)
    }

    pub fn optional_text(prompt: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input = Self::text(prompt)?;
        if input.is_empty() {
            Ok(None)
        } else {
            Ok(Some(input))
        }
    }

    fn read_bounded_line() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stdin = io::stdin().lock();
        let mut buffer = Vec::new();

        let limit = MAX_TOKEN_BYTES + 8;
        stdin
            .by_ref()
            .take(limit as u64)
            .read_until(b'\n', &mut buffer)?;

        Ok(buffer)
    }
}
