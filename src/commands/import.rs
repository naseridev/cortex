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

        let mut imported = 0;
        let mut skipped = 0;
        let mut failed = 0;

        for entry in import_data.entries {
            if entry.name.is_empty() {
                eprintln!("Skipping entry with empty name");
                failed += 1;
                continue;
            }

            if entry.name.starts_with("__") {
                eprintln!("Skipping reserved name: {}", entry.name);
                failed += 1;
                continue;
            }

            if let Err(e) = Password::length_check(&entry.password, MIN_ACCOUNT_PASSWORD_LENGTH) {
                eprintln!("Skipping '{}': {}", entry.name, e);
                failed += 1;
                continue;
            }

            if let Some(ref desc) = entry.description {
                if desc.len() > 500 {
                    eprintln!(
                        "Skipping '{}': Description too long (max 500 chars)",
                        entry.name
                    );
                    failed += 1;
                    continue;
                }

                if let Err(e) = Password::in_desc_check(&entry.password, desc) {
                    eprintln!("Skipping '{}': {}", entry.name, e);
                    failed += 1;
                    continue;
                }
            }

            let normalized_tags = TagValidator::normalize(&entry.tags);
            if let Err(e) = TagValidator::validate(&normalized_tags) {
                eprintln!("Skipping '{}': {}", entry.name, e);
                failed += 1;
                continue;
            }

            let exists = storage.entry_exists(&entry.name)?;

            if exists && !overwrite {
                eprintln!(
                    "Skipping '{}': already exists (use --overwrite to replace)",
                    entry.name
                );
                skipped += 1;
                continue;
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
                            }
                            imported += 1;
                        }
                        Ok(false) => {
                            eprintln!("Failed to import: {}", entry.name);
                            failed += 1;
                        }
                        Err(e) => {
                            eprintln!("Error importing '{}': {}", entry.name, e);
                            failed += 1;
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
}
