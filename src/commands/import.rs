use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password, tags::TagValidator},
};
use serde::Deserialize;
use std::{fs::File, io::BufReader, path::Path};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

#[derive(Deserialize)]
struct ImportData {
    version: String,
    timestamp: u64,
    entries: Vec<ImportEntry>,
}

#[derive(Deserialize)]
struct ImportEntry {
    name: String,
    password: String,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub struct Import;

impl Import {
    pub fn new(file_path: String, overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
        if file_path.is_empty() {
            return Err("File path cannot be empty".into());
        }

        let path = Path::new(&file_path);

        let file = File::open(path).map_err(|_| format!("File not found: {}", file_path))?;
        let reader = BufReader::new(file);
        let import_data: ImportData =
            serde_json::from_reader(reader).map_err(|e| format!("Invalid JSON format: {}", e))?;

        if import_data.entries.is_empty() {
            return Err("No entries found in import file".into());
        }

        println!("\nImport Summary:");
        println!("  Version: {}", import_data.version);
        println!("  Timestamp: {}", import_data.timestamp);
        println!("  Total entries: {}", import_data.entries.len());
        println!();

        let (storage, crypto) = Gateway::login()?;

        let mut validated_entries = Vec::new();
        let mut validation_errors = Vec::new();

        for entry in import_data.entries {
            if entry.name.is_empty() {
                validation_errors.push(format!("Entry with empty name"));
                continue;
            }

            if entry.name.starts_with("__") {
                validation_errors.push(format!("Reserved name: {}", entry.name));
                continue;
            }

            if let Err(e) = Password::length_check(&entry.password, MIN_ACCOUNT_PASSWORD_LENGTH) {
                validation_errors.push(format!("{}: {}", entry.name, e));
                continue;
            }

            if let Some(ref desc) = entry.description {
                if desc.len() > 500 {
                    validation_errors.push(format!("{}: Description too long", entry.name));
                    continue;
                }

                if let Err(e) = Password::in_desc_check(&entry.password, desc) {
                    validation_errors.push(format!("{}: {}", entry.name, e));
                    continue;
                }
            }

            let normalized_tags = TagValidator::normalize(&entry.tags);
            if let Err(e) = TagValidator::validate(&normalized_tags) {
                validation_errors.push(format!("{}: {}", entry.name, e));
                continue;
            }

            validated_entries.push((entry, normalized_tags));
        }

        if !validation_errors.is_empty() {
            eprintln!("\nValidation errors:");
            for error in &validation_errors {
                eprintln!("  - {}", error);
            }
        }

        let mut imported_names = Vec::new();
        let mut original_entries = Vec::new();

        let mut imported = 0;
        let mut skipped = 0;
        let mut failed = 0;

        for (entry, normalized_tags) in validated_entries {
            let exists = storage.entry_exists(&entry.name)?;

            if exists && !overwrite {
                eprintln!(
                    "Skipping '{}': already exists (use --overwrite to replace)",
                    entry.name
                );
                skipped += 1;
                continue;
            }

            if exists {
                if let Ok(Some(original)) = storage.get_password(&entry.name) {
                    original_entries.push((entry.name.clone(), original));
                }
            }

            let tag_list = if normalized_tags.is_empty() {
                None
            } else {
                Some(normalized_tags.as_slice())
            };

            match crypto.create_entry(
                &SecureString::new(entry.password.clone()).as_bytes(),
                entry.description.as_deref(),
                tag_list,
            ) {
                Ok(password_entry) => {
                    let result = if exists {
                        storage.edit_password(&entry.name, &password_entry)
                    } else {
                        storage.create_password(&entry.name, &password_entry)
                    };

                    match result {
                        Ok(true) => {
                            if exists {
                                println!("Updated: {}", entry.name);
                            } else {
                                println!("Imported: {}", entry.name);
                                imported_names.push(entry.name.clone());
                            }
                            imported += 1;
                        }
                        Ok(false) => {
                            eprintln!("Failed to import: {}", entry.name);
                            failed += 1;
                        }
                        Err(e) => {
                            eprintln!("Error importing '{}': {}", entry.name, e);
                            Self::rollback_import(&storage, &imported_names, &original_entries)?;
                            return Err(format!("Import failed, changes rolled back: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error creating entry for '{}': {}", entry.name, e);
                    failed += 1;
                }
            }
        }

        println!("\nImport completed:");
        println!("  Imported: {}", imported);
        if skipped > 0 {
            println!("  Skipped: {}", skipped);
        }
        if failed > 0 {
            println!("  Failed: {}", failed);
        }

        Ok(())
    }

    fn rollback_import(
        storage: &crate::core::storage::Storage,
        imported_names: &[String],
        original_entries: &[(String, crate::core::types::PasswordEntry)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("\nRolling back changes...");

        for name in imported_names {
            let _ = storage.delete_password(name);
        }

        for (name, entry) in original_entries {
            let _ = storage.edit_password(name, entry);
        }

        storage.flush()?;
        eprintln!("Rollback completed.");

        Ok(())
    }
}
