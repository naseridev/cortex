use crate::{
    core::{crypto::Crypto, storage::Storage},
    modules::{session::Session, validation::Validation},
    ui::prompt::UserPrompt,
};

pub struct Gateway;

impl Gateway {
    pub fn login() -> Result<(Storage, Crypto), Box<dyn std::error::Error>> {
        Validation::storage_probe(true, "Database not initialized. Use 'init' command.")?;

        let storage = Storage::new()?;

        if let Ok(Some(cached_password)) = Session::load_session() {
            let crypto = Crypto::new(&cached_password);
            if let Ok(Some(entry)) = storage.get_init_marker() {
                if crypto.verify_test_data(&entry) {
                    return Ok((storage, crypto));
                }
            }
            Session::clear_session().ok();
        }

        let mut failure = 0;
        loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);

            let is_correct = match storage.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                Session::save_session(&master_password).ok();
                return Ok((storage, crypto));
            } else if failure > 1 {
                Session::clear_session().ok();
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        }
    }

    pub fn login_storage_only() -> Result<Storage, Box<dyn std::error::Error>> {
        let (storage, _) = Self::login()?;
        Ok(storage)
    }
}
