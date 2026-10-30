use crate::{
    core::{config::Config, crypto::Crypto, storage::Storage},
    modules::{session::Session, validation::Validation},
    ui::prompt::UserPrompt,
};

pub struct Gateway;

impl Gateway {
    pub fn login() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        Validation::storage_probe(true, "Database not initialized. Use 'init' command.")?;

        let storage = Storage::new()?;

        Config::clear_cache();
        Config::load_from_db(&storage.db)?;

        let salt = storage
            .get_salt()?
            .ok_or("Database salt not found. Database may be corrupted.")?;

        if let Some(cached_password) = Session::load_session()? {
            let crypto = Crypto::new(&cached_password, &salt);
            if let Some(verification_data) = storage.get_verification_data()?
                && Crypto::verify_password(&cached_password, &salt, &verification_data)
            {
                return Ok((storage, crypto));
            }
            Session::clear_session()?;
        }

        let mut failure = 0;
        loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password, &salt);

            let is_correct = match storage.get_verification_data()? {
                Some(verification_data) => {
                    Crypto::verify_password(&master_password, &salt, &verification_data)
                }
                None => false,
            };

            if is_correct {
                Session::save_session(&master_password)?;
                return Ok((storage, crypto));
            } else if failure >= 2 {
                Session::clear_session()?;
                return Err("Authentication failed".into());
            }
            eprintln!("Sorry, try again.\n");
            failure += 1;
        }
    }

    pub fn login_storage_only() -> Result<Storage, Box<dyn std::error::Error>> {
        let (storage, _) = Self::login()?;
        Ok(storage)
    }
}
