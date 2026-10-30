use crate::core::storage::Storage;

pub struct Validation;

impl Validation {
    pub fn storage_probe(
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = Storage::database_exists()?;

        if exists != should_exist {
            return Err(error_message.into());
        }

        Ok(())
    }

    pub fn account_exists_probe(
        storage: &Storage,
        name: &str,
        should_exist: bool,
        error_message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exists = storage.entry_exists(name)?;

        if exists != should_exist {
            return Err(error_message.into());
        }

        Ok(())
    }
}
