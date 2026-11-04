use rand::seq::{IndexedRandom, SliceRandom};
use zeroize::Zeroize;

const SPECIAL_CHARACTERS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT_CHARS: &str = "0123456789";
const MIN_MASTER_PASSWORD_CHARS: usize = 8;
const MIN_COMPARED_CHARS: usize = 3;
const MAX_COMPARED_WINDOW: usize = 8;

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
        let any_flag_set =
            charset.uppercase() || charset.lowercase() || charset.digits() || charset.special();
        let include_when_selected = |selected: bool| !any_flag_set || selected;

        let classes = [
            (include_when_selected(charset.lowercase()), LOWERCASE_CHARS),
            (include_when_selected(charset.uppercase()), UPPERCASE_CHARS),
            (include_when_selected(charset.digits()), DIGIT_CHARS),
            (include_when_selected(charset.special()), SPECIAL_CHARACTERS),
        ];

        let mut pool: Vec<char> = Vec::new();
        let mut required_chars: Vec<char> = Vec::new();

        for (enabled, class) in classes {
            if enabled {
                let class_chars: Vec<char> = class.chars().collect();
                required_chars.push(Self::pick_random_char(&class_chars)?);
                pool.extend_from_slice(&class_chars);
            }
        }

        if pool.is_empty() {
            required_chars.zeroize();
            return Err("No character types selected".to_string());
        }

        if required_chars.len() > length {
            pool.zeroize();
            required_chars.zeroize();
            return Err("Password length too short for required character types".to_string());
        }

        let mut rng = rand::rng();
        let fill_count = length - required_chars.len();
        let mut password_chars = required_chars;

        for _ in 0..fill_count {
            let Some(&ch) = pool.choose(&mut rng) else {
                pool.zeroize();
                password_chars.zeroize();
                return Err("No character types selected".to_string());
            };
            password_chars.push(ch);
        }

        pool.zeroize();
        password_chars.shuffle(&mut rng);
        let result: String = password_chars.iter().copied().collect();
        password_chars.zeroize();
        Ok(result)
    }

    fn pick_random_char(chars: &[char]) -> Result<char, String> {
        let mut rng = rand::rng();
        chars
            .choose(&mut rng)
            .copied()
            .ok_or_else(|| "Empty charset".to_string())
    }

    pub fn security_check(password: &str) -> Result<(), String> {
        if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err(format!(
                "Password must be at least {MIN_MASTER_PASSWORD_CHARS} characters long"
            ));
        }

        let missing: Vec<&str> = [
            (password.chars().any(char::is_lowercase), "lowercase letter"),
            (password.chars().any(char::is_uppercase), "uppercase letter"),
            (password.chars().any(|c| c.is_ascii_digit()), "digit"),
            (
                password.chars().any(|c| SPECIAL_CHARACTERS.contains(c)),
                "special character",
            ),
        ]
        .into_iter()
        .filter(|(present, _)| !*present)
        .map(|(_, label)| label)
        .collect();

        if missing.is_empty() {
            return Ok(());
        }

        Err(format!(
            "Your password needs improvement.\nMissing: {}",
            missing.join(", ")
        ))
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
        let mut password_chars: Vec<char> = password.to_lowercase().chars().collect();
        let mut description_lower = description.to_lowercase();

        if password_chars.len() < MIN_COMPARED_CHARS
            || description_lower.chars().count() < MIN_COMPARED_CHARS
        {
            password_chars.zeroize();
            description_lower.zeroize();
            return false;
        }

        let window_size = (password_chars.len() / 2).clamp(MIN_COMPARED_CHARS, MAX_COMPARED_WINDOW);
        let found = password_chars.windows(window_size).any(|window| {
            let mut fragment: String = window.iter().collect();
            let hit = description_lower.contains(&fragment);
            fragment.zeroize();
            hit
        });

        password_chars.zeroize();
        description_lower.zeroize();
        found
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
