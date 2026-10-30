use zeroize::Zeroize;

use crate::{
    core::{
        config::Config,
        crypto::Crypto,
        storage::Storage,
        types::{SecureString, decode_secret_text},
    },
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
        let verification = storage
            .get_verification_data()?
            .ok_or("Database verification data not found. Database may be corrupted.")?;

        if let Some(mut cached_key) = Session::load_session()? {
            let crypto = Crypto::from_key(cached_key);
            cached_key.zeroize();
            if crypto.matches_verification(&verification) {
                return Ok((storage, crypto));
            }
            Session::clear_session()?;
        }

        let mut failure = 0;
        loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::open(&master_password, &salt)?;

            if crypto.matches_verification(&verification) {
                let crypto = Self::migrate_legacy(&storage, crypto, &master_password)?;
                Session::save_session(crypto.key())?;
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

    fn migrate_legacy(
        storage: &Storage,
        crypto: Crypto,
        master_password: &SecureString,
    ) -> Result<Crypto, Box<dyn std::error::Error>> {
        if !crypto.is_legacy() {
            return Ok(crypto);
        }

        println!("Upgrading vault to Argon2id...");
        let entries = storage.get_all_entries()?;
        let mut decrypted_entries = Vec::new();

        for (name, entry) in &entries {
            let decrypted = crypto.decrypt_entry(name, entry)?;
            let password = SecureString::new(decode_secret_text(decrypted)?);
            let description = crypto.decrypt_description(name, entry)?;
            let tags = crypto.decrypt_tags(name, entry)?;
            decrypted_entries.push((name.clone(), password, description, tags));
        }

        let (new_crypto, salt_blob) = Crypto::create(master_password)?;
        let mut updated_entries = Vec::with_capacity(decrypted_entries.len());
        for (name, password, description, tags) in &decrypted_entries {
            let tag_list = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };
            let new_entry = new_crypto.create_entry(
                name,
                password.as_bytes(),
                description.as_deref(),
                tag_list,
            )?;
            updated_entries.push((name.clone(), new_entry));
        }

        storage.atomic_reset(&updated_entries, &new_crypto.verification(), &salt_blob)?;
        println!("Vault encryption upgraded.");
        Ok(new_crypto)
    }
}
