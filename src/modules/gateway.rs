use crate::{
    core::{
        accounts::Accounts,
        crypto::Crypto,
        limits::{
            MAX_PASSWORD_ATTEMPTS_PER_RUN, THROTTLE_FREE_FAILURES, THROTTLE_MAX_DELAY_SECONDS,
        },
        storage::Storage,
        validation::Validation,
    },
    modules::session::Session,
    ui::prompt::UserPrompt,
};
use std::{thread, time::Duration};
use zeroize::Zeroize;

pub struct Gateway;

struct VaultHeader {
    salt: Vec<u8>,
    verification: Vec<u8>,
}

impl Gateway {
    pub fn login() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (name, storage, header) = Self::open_vault()?;

        if let Some(crypto) = Self::restore_agent_key(&name, &header)? {
            return Self::finish_login(storage, crypto);
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;
        Self::finish_login(storage, crypto)
    }

    pub fn login_for_recovery() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (name, storage, header) = Self::open_vault()?;

        if let Some(crypto) = Self::restore_agent_key(&name, &header)? {
            storage.bind_integrity(&crypto);
            return Ok((storage, crypto));
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;
        storage.bind_integrity(&crypto);
        Ok((storage, crypto))
    }

    pub fn login_account(name: &str) -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (storage, header) = Self::open_account_vault(name)?;

        if let Some(crypto) = Self::restore_agent_key(name, &header)? {
            return Self::finish_login(storage, crypto);
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;
        Self::finish_login(storage, crypto)
    }

    pub fn login_account_for_recovery(
        name: &str,
    ) -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (storage, header) = Self::open_account_vault(name)?;

        if let Some(crypto) = Self::restore_agent_key(name, &header)? {
            storage.bind_integrity(&crypto);
            return Ok((storage, crypto));
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;

        storage.bind_integrity(&crypto);
        Ok((storage, crypto))
    }

    pub fn login_with_session() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (name, storage, header) = Self::open_vault()?;

        if let Some(crypto) = Self::restore_agent_key(&name, &header)? {
            return Self::finish_login(storage, crypto);
        }

        if let Some(crypto) = Self::restore_session(&header)? {
            return Self::finish_login(storage, crypto);
        }

        let crypto = Self::prompt_master_key(&storage, &header)?;
        let (storage, crypto) = Self::finish_login(storage, crypto)?;

        if let Err(error) = Session::save_session(crypto.key()) {
            eprintln!("Warning: session could not be stored: {error}");
        }

        Ok((storage, crypto))
    }

    pub fn login_for_mcp(name: &str) -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        let (storage, header) = Self::open_existing_account_vault(name)?;

        if let Some(crypto) = Self::restore_agent_key(name, &header)? {
            return Self::finish_login(storage, crypto);
        }

        if Accounts::active()?.as_deref() == Some(name)
            && let Some(mut key) = Session::load_session()?
        {
            let crypto = Crypto::from_key(key);
            key.zeroize();
            if crypto.matches_verification(&header.verification) {
                return Self::finish_login(storage, crypto);
            }
        }

        Err(format!(
            "Account '{name}' is locked. Inform the user to unlock their vault in the terminal first, or use an [agent] account."
        )
        .into())
    }

    pub fn login_storage_only() -> Result<Storage, Box<dyn std::error::Error>> {
        let (storage, _) = Self::login()?;
        Ok(storage)
    }

    fn restore_agent_key(
        name: &str,
        header: &VaultHeader,
    ) -> Result<Option<Crypto>, Box<dyn std::error::Error>> {
        let Some(mut key) = Accounts::get_agent_key(name)? else {
            return Ok(None);
        };

        let crypto = Crypto::from_key(key);
        key.zeroize();

        if crypto.matches_verification(&header.verification) {
            return Ok(Some(crypto));
        }

        Ok(None)
    }

    fn restore_session(header: &VaultHeader) -> Result<Option<Crypto>, Box<dyn std::error::Error>> {
        let Some(mut key) = Session::load_session()? else {
            return Ok(None);
        };

        let crypto = Crypto::from_key(key);
        key.zeroize();

        if crypto.matches_verification(&header.verification) {
            return Ok(Some(crypto));
        }

        Session::clear_session()?;
        Ok(None)
    }

    fn finish_login(
        storage: Storage,
        crypto: Crypto,
    ) -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        storage.bind_integrity(&crypto);
        storage.verify_integrity()?;
        Ok((storage, crypto))
    }

    fn open_vault() -> Result<(String, Storage, VaultHeader), Box<dyn std::error::Error>> {
        Validation::storage_probe(true, "No accounts found. Create one with 'account create'.")?;

        let active =
            Accounts::active()?.ok_or("No accounts found. Create one with 'account create'.")?;
        let storage = Storage::open_account(&active)?;
        let (storage, header) = Self::read_header(storage)?;

        Ok((active, storage, header))
    }

    fn open_account_vault(
        name: &str,
    ) -> Result<(Storage, VaultHeader), Box<dyn std::error::Error>> {
        let (accounts, _) = Accounts::list()?;

        if accounts.is_empty() {
            return Err("No accounts found. Create one with 'account create'.".into());
        }

        if !Accounts::exists(name)? {
            return Err(format!("Account '{name}' not found.").into());
        }

        let storage = Storage::open_account(name)?;
        Self::read_header(storage)
    }

    fn open_existing_account_vault(
        name: &str,
    ) -> Result<(Storage, VaultHeader), Box<dyn std::error::Error>> {
        if !Accounts::exists(name)? {
            return Err(format!("Account '{name}' not found.").into());
        }

        let storage = Storage::open_account(name)?;
        Self::read_header(storage)
    }

    fn read_header(storage: Storage) -> Result<(Storage, VaultHeader), Box<dyn std::error::Error>> {
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

#[must_use]
pub fn throttle_delay_seconds(failed_attempts: u32) -> u64 {
    let Some(exponent) = failed_attempts.checked_sub(THROTTLE_FREE_FAILURES) else {
        return 0;
    };

    1u64.checked_shl(exponent)
        .unwrap_or(u64::MAX)
        .min(THROTTLE_MAX_DELAY_SECONDS)
}
