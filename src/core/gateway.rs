use crate::{
    core::{
        accounts::{Accounts, NO_ACCOUNTS},
        crypto::Crypto,
        limits::{
            MAX_PASSWORD_ATTEMPTS_PER_RUN, THROTTLE_FREE_FAILURES, THROTTLE_MAX_DELAY_SECONDS,
        },
        session::Session,
        storage::Storage,
        validation::Validation,
    },
    ui::prompt::UserPrompt,
};
use std::{thread, time::Duration};
use zeroize::Zeroize;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

pub type Unlocked = (Storage, Crypto);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Integrity {
    Verify,
    Skip,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Prompt,
    PromptAndSession,
}

impl Source {
    fn uses_session(self) -> bool {
        self != Self::Prompt
    }
}

struct Vault {
    storage: Storage,
    salt: Vec<u8>,
    verification: Vec<u8>,
    is_active: bool,
}

pub struct Gateway;

impl Gateway {
    pub fn login() -> Fallible<Unlocked> {
        Self::unlock(Vault::open_active()?, Integrity::Verify, Source::Prompt)
    }

    pub fn login_for_recovery() -> Fallible<Unlocked> {
        Self::unlock(Vault::open_active()?, Integrity::Skip, Source::Prompt)
    }

    pub fn login_account(name: &str) -> Fallible<Unlocked> {
        Self::unlock(Vault::open_named(name)?, Integrity::Verify, Source::Prompt)
    }

    pub fn login_account_for_recovery(name: &str) -> Fallible<Unlocked> {
        Self::unlock(Vault::open_named(name)?, Integrity::Skip, Source::Prompt)
    }

    pub fn login_with_session() -> Fallible<Unlocked> {
        Self::unlock(
            Vault::open_active()?,
            Integrity::Verify,
            Source::PromptAndSession,
        )
    }

    pub fn login_storage_only() -> Fallible<Storage> {
        let (storage, _) = Self::login()?;
        Ok(storage)
    }

    fn unlock(vault: Vault, integrity: Integrity, source: Source) -> Fallible<Unlocked> {
        if vault.is_active
            && source.uses_session()
            && let Some(crypto) = vault.restore_session()?
        {
            return vault.finish(crypto, integrity);
        }

        match source {
            Source::Prompt => {
                let crypto = vault.prompt_master_key()?;
                vault.finish(crypto, integrity)
            }
            Source::PromptAndSession => {
                let crypto = vault.prompt_master_key()?;
                let (storage, crypto) = vault.finish(crypto, integrity)?;
                if let Err(error) = Session::save_session(crypto.key()) {
                    eprintln!("Warning: session could not be stored: {error}");
                }
                Ok((storage, crypto))
            }
        }
    }

    fn apply_throttle(storage: &Storage) -> Fallible<()> {
        let delay = Self::throttle_delay_seconds(storage.failed_attempts()?);

        if delay > 0 {
            eprintln!("Too many failed attempts. Waiting {delay}s before the next try.");
            thread::sleep(Duration::from_secs(delay));
        }

        Ok(())
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
}

impl Vault {
    fn open_active() -> Fallible<Self> {
        Validation::storage_probe(true, NO_ACCOUNTS)?;

        let (_, active) = Accounts::list()?;
        let name = active.ok_or(NO_ACCOUNTS)?;

        Self::load(&name, true)
    }

    fn open_named(name: &str) -> Fallible<Self> {
        let (accounts, active) = Accounts::list()?;
        let registered = accounts.iter().any(|account| account == name);

        if !registered || !Accounts::db_file_exists(name)? {
            return Err(format!("Account '{name}' not found.").into());
        }

        let is_active = active.as_deref() == Some(name);
        Self::load(name, is_active)
    }

    fn load(name: &str, is_active: bool) -> Fallible<Self> {
        let storage = Storage::open_account(name)?;
        let salt = storage
            .get_salt()?
            .ok_or("Database salt not found. Database may be corrupted.")?;
        let verification = storage
            .get_verification_data()?
            .ok_or("Database verification data not found. Database may be corrupted.")?;

        Ok(Self {
            storage,
            salt,
            verification,
            is_active,
        })
    }

    fn restore_session(&self) -> Fallible<Option<Crypto>> {
        let Some(key) = Session::load_session()? else {
            return Ok(None);
        };

        if let Some(crypto) = verified(key, &self.verification) {
            return Ok(Some(crypto));
        }

        Session::clear_session()?;
        Ok(None)
    }

    fn prompt_master_key(&self) -> Fallible<Crypto> {
        for attempt in 1..=MAX_PASSWORD_ATTEMPTS_PER_RUN {
            Gateway::apply_throttle(&self.storage)?;

            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::open(&master_password, &self.salt)?;

            if crypto.matches_verification(&self.verification) {
                self.storage.clear_failed_attempts()?;
                return Ok(crypto);
            }

            self.storage.record_failed_attempt()?;

            if attempt < MAX_PASSWORD_ATTEMPTS_PER_RUN {
                eprintln!("Sorry, try again.\n");
            }
        }

        if self.is_active {
            Session::clear_session()?;
        }
        Err("Authentication failed".into())
    }

    fn finish(self, crypto: Crypto, integrity: Integrity) -> Fallible<Unlocked> {
        self.storage.bind_integrity(&crypto);
        if integrity == Integrity::Verify {
            self.storage.verify_integrity()?;
        }
        Ok((self.storage, crypto))
    }
}

fn verified(mut key: [u8; 32], verification: &[u8]) -> Option<Crypto> {
    let crypto = Crypto::from_key(key);
    key.zeroize();
    crypto.matches_verification(verification).then_some(crypto)
}
