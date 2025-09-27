use crate::core::storage::Storage;
use std::process;

pub struct Validation;

impl Validation {
    pub fn storage_existence_probe() -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        Ok(())
    }
}
