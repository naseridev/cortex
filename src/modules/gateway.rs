use zeroize::Zeroize;

use crate::{
    core::{config::Config, crypto::Crypto, storage::Storage},
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
        let crypto = Self::prompt_master_key(&header)?;
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

        let crypto = Self::prompt_master_key(&header)?;
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

    fn prompt_master_key(header: &VaultHeader) -> Result<Crypto, Box<dyn std::error::Error>> {
        let mut failure = 0;
        loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::open(&master_password, &header.salt)?;

            if crypto.matches_verification(&header.verification) {
                return Ok(crypto);
            } else if failure >= 2 {
                Session::clear_session()?;
                return Err("Authentication failed".into());
            }
            eprintln!("Sorry, try again.\n");
            failure += 1;
        }
    }
}
