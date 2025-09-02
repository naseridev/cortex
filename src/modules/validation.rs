use regex::Regex;

pub struct Validation;

impl Validation {
    pub fn password_security(password: &str) -> Result<(), String> {
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

    pub fn password_in_desc_found(password: &str, description: &str) -> bool {
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
