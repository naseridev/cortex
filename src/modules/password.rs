use rand::{RngCore, rngs::OsRng};
use regex::Regex;

pub struct Password;

impl Password {
    pub fn generate(
        length: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        special: bool,
    ) -> Result<String, String> {
        let mut charset = String::new();
        let mut required_chars = Vec::new();

        let any_flag_set = uppercase || lowercase || digits || special;

        let use_lowercase = if any_flag_set { lowercase } else { true };
        let use_uppercase = if any_flag_set { uppercase } else { true };
        let use_digits = if any_flag_set { digits } else { true };
        let use_special = if any_flag_set { special } else { true };

        if use_lowercase {
            let lower = "abcdefghijklmnopqrstuvwxyz";
            charset.push_str(lower);
            required_chars.push(Self::pick_random_char(lower)?);
        }

        if use_uppercase {
            let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            charset.push_str(upper);
            required_chars.push(Self::pick_random_char(upper)?);
        }

        if use_digits {
            let nums = "0123456789";
            charset.push_str(nums);
            required_chars.push(Self::pick_random_char(nums)?);
        }

        if use_special {
            let specs = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            charset.push_str(specs);
            required_chars.push(Self::pick_random_char(specs)?);
        }

        if charset.is_empty() {
            return Err("No character types selected".to_string());
        }

        if required_chars.len() > length {
            return Err("Password length too short for required character types".to_string());
        }

        let charset_chars: Vec<char> = charset.chars().collect();

        let mut password = String::with_capacity(length);
        let mut rng = OsRng;

        for &ch in &required_chars {
            password.push(ch);
        }

        for _ in required_chars.len()..length {
            let idx = (rng.next_u32() as usize) % charset_chars.len();
            password.push(charset_chars[idx]);
        }

        let mut password_chars: Vec<char> = password.chars().collect();

        for i in (1..password_chars.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            password_chars.swap(i, j);
        }

        Ok(password_chars.iter().collect())
    }

    fn pick_random_char(charset: &str) -> Result<char, String> {
        let chars: Vec<char> = charset.chars().collect();

        if chars.is_empty() {
            return Err("Empty charset".to_string());
        }

        let mut rng = OsRng;
        let idx = (rng.next_u32() as usize) % chars.len();

        Ok(chars[idx])
    }

    pub fn security_check(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        let mut missing = Vec::new();

        if !password.chars().any(|c| c.is_lowercase()) {
            missing.push("lowercase letter");
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            missing.push("uppercase letter");
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            missing.push("digit");
        }

        if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            missing.push("special character");
        }

        if missing.len() > 1 {
            return Err(format!(
                "Your password needs improvement.\nMissing: {}",
                missing.join(", ")
            ));
        }

        Ok(())
    }

    pub fn in_desc_found(password: &str, description: &str) -> bool {
        if password.len() < 3 {
            return false;
        }

        let password_lower = password.to_lowercase();
        let description_lower = description.to_lowercase();

        if description_lower.contains(&password_lower) {
            return true;
        }

        let password_chars: Vec<char> = password_lower.chars().collect();
        let description_chars: Vec<char> = description_lower.chars().collect();

        for window_size in (password.len().min(8)..=password.len()).rev() {
            for window in password_chars.windows(window_size) {
                let pattern: String = window.iter().collect();
                if pattern.len() >= 3
                    && description_chars.windows(window_size).any(|desc_window| {
                        let desc_pattern: String = desc_window.iter().collect();
                        desc_pattern == pattern
                    })
                {
                    return true;
                }
            }
        }

        let regex_pattern = format!(r"(?i){}", regex::escape(password));

        if let Ok(re) = Regex::new(&regex_pattern) {
            if re.is_match(description) {
                return true;
            }
        }

        false
    }
}
