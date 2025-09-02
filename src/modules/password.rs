use rand::{RngCore, rngs::OsRng};

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
}
