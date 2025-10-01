use crate::core::storage::Storage;
use std::process;

pub struct Validation;

impl Validation {
    pub fn storage_probe(
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = Storage::database_exists();

        if exists != should_exist {
            eprintln!("{}", error_message);
            process::exit(1);
        }

        Ok(())
    }

    pub fn account_exists_probe(
        storage: &Storage,
        name: &str,
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = storage.db.get(name)?.is_some();

        if exists != should_exist {
            eprintln!("{}", error_message);
            process::exit(1);
        }

        Ok(())
    }
}
