use crate::modules::password::Password;

pub struct Pass;

impl Pass {
    pub fn execute(
        length: usize,
        count: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        special: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if length < 4 {
            return Err("Password length must be at least 4 characters.".into());
        }

        if length > 128 {
            return Err("Password length too long (max 128 chars).".into());
        }

        if !(1..=50).contains(&count) {
            return Err("Count must be between 1 and 50.".into());
        }

        for i in 1..=count {
            let password = Password::generate(length, uppercase, lowercase, digits, special)?;
            if count > 1 {
                println!("{}: {}", i, password);
            } else {
                println!("{}", password);
            }
        }

        Ok(())
    }
}
