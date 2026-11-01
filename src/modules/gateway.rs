use std::{thread, time::Duration};
use zeroize::Zeroize;

use crate::{
    core::{
        config::Config,
        crypto::Crypto,
        limits::{
            MAX_PASSWORD_ATTEMPTS_PER_RUN, THROTTLE_FREE_FAILURES, THROTTLE_MAX_DELAY_SECONDS,
        },
        storage::Storage,
    },
    modules::{session::Session, validation::Validation},
    ui::prompt::UserPrompt,
};

pub struct Gateway;

struct VaultHeader {
    salt: Vec<u8>,
    verification: Vec<u8>,
}

impl Gateway {
    pub fn login() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (storage, header) = Self::open_vault()?;
        let crypto = Self::prompt_master_key(&storage, &header)?;
        Ok((storage, crypto))
    }

    pub fn login_with_session() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (storage, header) = Self::open_vault()?;

        if let Some(mut key) = Session::load_session()? {
            let crypto = Crypto::from_key(key);
            key.zeroize();
            if crypto.matches_verification(&header.verification) {
                return Ok((storage, crypto));
            }
            Session::clear_session()?;
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;
        if let Err(error) = Session::save_session(crypto.key()) {
            eprintln!("Warning: session could not be stored: {error}");
        }
        Ok((storage, crypto))
    }

    pub fn login_storage_only() -> Result<Storage, Box<dyn std::error::Error>> {
        let (storage, _) = Self::login()?;
        Ok(storage)
    }

    fn open_vault() -> Result<(Storage, VaultHeader), Box<dyn std::error::Error>> {
        Validation::storage_probe(true, "Database not initialized. Use 'init' command.")?;

        let storage = Storage::new()?;

        Config::clear_cache();
        Config::load_from_db(&storage.db)?;

        let salt = storage
            .get_salt()?
            .ok_or("Database salt not found. Database may be corrupted.")?;
        let verification = storage
            .get_verification_data()?
            .ok_or("Database verification data not found. Database may be corrupted.")?;

        Ok((storage, VaultHeader { salt, verification }))
    }

    fn prompt_master_key(
        storage: &Storage,
        header: &VaultHeader,
    ) -> Result<Crypto, Box<dyn std::error::Error>> {
        for attempt in 1..=MAX_PASSWORD_ATTEMPTS_PER_RUN {
            Self::apply_throttle(storage)?;
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::open(&master_password, &header.salt)?;

            if crypto.matches_verification(&header.verification) {
                storage.clear_failed_attempts()?;
                return Ok(crypto);
            }

            storage.record_failed_attempt()?;
            if attempt < MAX_PASSWORD_ATTEMPTS_PER_RUN {
                eprintln!("Sorry, try again.\n");
            }
        }

        Session::clear_session()?;
        Err("Authentication failed".into())
    }

    fn apply_throttle(storage: &Storage) -> Result<(), Box<dyn std::error::Error>> {
        let delay = throttle_delay_seconds(storage.failed_attempts()?);
        if delay > 0 {
            eprintln!("Too many failed attempts. Waiting {delay}s before the next try.");
            thread::sleep(Duration::from_secs(delay));
        }
        Ok(())
    }
}

fn throttle_delay_seconds(failed_attempts: u32) -> u64 {
    let Some(exponent) = failed_attempts.checked_sub(THROTTLE_FREE_FAILURES) else {
        return 0;
    };
    1u64.checked_shl(exponent)
        .unwrap_or(u64::MAX)
        .min(THROTTLE_MAX_DELAY_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::throttle_delay_seconds;

    #[test]
    fn no_delay_within_free_failures() {
        assert_eq!(throttle_delay_seconds(0), 0);
        assert_eq!(throttle_delay_seconds(2), 0);
    }

    #[test]
    fn delay_doubles_after_free_failures() {
        assert_eq!(throttle_delay_seconds(3), 1);
        assert_eq!(throttle_delay_seconds(4), 2);
        assert_eq!(throttle_delay_seconds(5), 4);
    }

    #[test]
    fn delay_is_capped_and_never_overflows() {
        assert_eq!(throttle_delay_seconds(u32::MAX), 3_600);
        assert_eq!(throttle_delay_seconds(100), 3_600);
    }
}
