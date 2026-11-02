use crate::core::{
    limits::MIN_ACCOUNT_PASSWORD_LENGTH,
    password::{Password, PasswordCharset},
};

const MAX_PASSWORD_LENGTH: usize = 128;
const MIN_COUNT: usize = 1;
const MAX_COUNT: usize = 50;

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

        if length > MAX_PASSWORD_LENGTH {
            return Err("Password length too long (max 128 chars).".into());
        }

        if !(MIN_COUNT..=MAX_COUNT).contains(&count) {
            return Err("Count must be between 1 and 50.".into());
        }

        for index in 1..=count {
            let password = Password::generate(length, charset)?;

            if count > 1 {
                println!("{index}: {password}");
            } else {
                println!("{password}");
            }
        }

        Ok(())
    }
}
