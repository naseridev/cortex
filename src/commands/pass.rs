use crate::{
    core::limits::MIN_ACCOUNT_PASSWORD_LENGTH,
    core::password::{Password, PasswordCharset},
};

pub struct Pass;

impl Pass {
    pub fn execute(
        length: usize,
        count: usize,
        charset: PasswordCharset,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if length < MIN_ACCOUNT_PASSWORD_LENGTH {
            return Err(format!(
                "Password length must be at least {MIN_ACCOUNT_PASSWORD_LENGTH} characters."
            )
            .into());
        }

        if length > 128 {
            return Err("Password length too long (max 128 chars).".into());
        }

        if !(1..=50).contains(&count) {
            return Err("Count must be between 1 and 50.".into());
        }

        for i in 1..=count {
            let password = Password::generate(length, charset)?;
            if count > 1 {
                println!("{i}: {password}");
            } else {
                println!("{password}");
            }
        }

        Ok(())
    }
}
