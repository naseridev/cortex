use rand::{Rng, rngs::OsRng};

#[derive(Clone, Copy)]
pub struct PasswordCharset(u8);

impl PasswordCharset {
    pub const UPPERCASE: u8 = 1;
    pub const LOWERCASE: u8 = 2;
    pub const DIGITS: u8 = 4;
    pub const SPECIAL: u8 = 8;

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn uppercase(self) -> bool {
        self.0 & Self::UPPERCASE != 0
    }

    #[must_use]
    pub const fn lowercase(self) -> bool {
        self.0 & Self::LOWERCASE != 0
    }

    #[must_use]
    pub const fn digits(self) -> bool {
        self.0 & Self::DIGITS != 0
    }

    #[must_use]
    pub const fn special(self) -> bool {
        self.0 & Self::SPECIAL != 0
    }
}

pub struct Password;

impl Password {
    pub fn generate(length: usize, charset: PasswordCharset) -> Result<String, String> {
        let mut pool = Vec::new();
        let mut required_chars = Vec::new();

        let any_flag_set =
            charset.uppercase() || charset.lowercase() || charset.digits() || charset.special();

        let use_lowercase = if any_flag_set {
            charset.lowercase()
        } else {
            true
        };
        let use_uppercase = if any_flag_set {
            charset.uppercase()
        } else {
            true
        };
        let use_digits = if any_flag_set { charset.digits() } else { true };
        let use_special = if any_flag_set {
            charset.special()
        } else {
            true
        };

        if use_lowercase {
            let lower: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
            required_chars.push(Self::pick_random_char(&lower)?);
            pool.extend_from_slice(&lower);
        }

        if use_uppercase {
            let upper: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
            required_chars.push(Self::pick_random_char(&upper)?);
            pool.extend_from_slice(&upper);
        }

        if use_digits {
            let nums: Vec<char> = "0123456789".chars().collect();
            required_chars.push(Self::pick_random_char(&nums)?);
            pool.extend_from_slice(&nums);
        }

        if use_special {
            let specs: Vec<char> = "!@#$%^&*()_+-=[]{}|;:,.<>?".chars().collect();
            required_chars.push(Self::pick_random_char(&specs)?);
            pool.extend_from_slice(&specs);
        }

        if pool.is_empty() {
            return Err("No character types selected".to_string());
        }

        if required_chars.len() > length {
            return Err("Password length too short for required character types".to_string());
        }

        let mut rng = OsRng;
        let mut password_chars = Vec::with_capacity(length);

        for &ch in &required_chars {
            password_chars.push(ch);
        }

        for _ in required_chars.len()..length {
            let idx = rng.gen_range(0..pool.len());
            password_chars.push(pool[idx]);
        }

        for i in (1..password_chars.len()).rev() {
            let j = rng.gen_range(0..=i);
            password_chars.swap(i, j);
        }

        Ok(password_chars.into_iter().collect())
    }

    fn pick_random_char(chars: &[char]) -> Result<char, String> {
        if chars.is_empty() {
            return Err("Empty charset".to_string());
        }

        let mut rng = OsRng;
        let idx = rng.gen_range(0..chars.len());
        Ok(chars[idx])
    }

    pub fn security_check(password: &str) -> Result<(), String> {
        if password.chars().count() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        let mut missing = Vec::new();

        if !password.chars().any(char::is_lowercase) {
            missing.push("lowercase letter");
        }

        if !password.chars().any(char::is_uppercase) {
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

        if !missing.is_empty() {
            return Err(format!(
                "Your password needs improvement.\nMissing: {}",
                missing.join(", ")
            ));
        }

        Ok(())
    }

    pub fn match_check(
        left_password: &str,
        right_password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if left_password != right_password {
            return Err("Password mismatch".into());
        }

        Ok(())
    }

    pub fn length_check(
        password: &str,
        min_length: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if password.chars().count() < min_length {
            return Err(format!("Password must be at least {min_length} characters").into());
        }

        Ok(())
    }

    fn in_desc_found(password: &str, description: &str) -> bool {
        let password_lower = password.to_lowercase();
        let description_lower = description.to_lowercase();

        let password_chars: Vec<char> = password_lower.chars().collect();
        let description_chars: Vec<char> = description_lower.chars().collect();

        if password_chars.len() < 3 || description_chars.is_empty() {
            return false;
        }

        if description_lower.contains(&password_lower) {
            return true;
        }

        if description_chars.len() < 3 {
            return false;
        }

        let min_window = (password_chars.len() / 2).max(3);

        for window_size in (min_window..=password_chars.len()).rev() {
            if window_size > description_chars.len() {
                continue;
            }

            for window in password_chars.windows(window_size) {
                if description_chars
                    .windows(window_size)
                    .any(|desc_window| desc_window == window)
                {
                    return true;
                }
            }
        }

        false
    }

    pub fn in_desc_check(
        password: &str,
        description: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if Self::in_desc_found(password, description) {
            return Err("Description cannot contain the password or parts of it.".into());
        }

        Ok(())
    }
}
