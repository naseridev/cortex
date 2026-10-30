use crate::{
    core::{
        crypto::Crypto,
        storage::Storage,
        types::{ExportData, ExportEntry, PasswordEntry, SecureString},
    },
    modules::{gateway::Gateway, password::Password, tags::TagValidator},
};
use std::collections::HashSet;
use std::{fs::File, io::BufReader, path::Path};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Import;

impl Import {
    pub fn execute(file_path: &str, overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
        let import_data = Self::read_file(file_path)?;

        println!("\nImport Summary:");
        println!("  Version: {}", import_data.version);
        println!("  Timestamp: {}", import_data.timestamp);
        println!("  Total entries: {}", import_data.entries.len());
        println!();

        let (storage, crypto) = Gateway::login()?;
        let (validated_entries, validation_errors) = Self::validate_entries(import_data.entries);

        if !validation_errors.is_empty() {
            eprintln!("\nValidation errors:");
            for error in &validation_errors {
                eprintln!("  - {error}");
            }
        }

        Self::apply_entries(&storage, &crypto, validated_entries, overwrite)
    }

    fn read_file(file_path: &str) -> Result<ExportData, Box<dyn std::error::Error>> {
        if file_path.trim().is_empty() {
            return Err("File path cannot be empty".into());
        }

        let file =
            File::open(Path::new(file_path)).map_err(|_| format!("File not found: {file_path}"))?;
        let reader = BufReader::new(file);
        let import_data: ExportData =
            serde_json::from_reader(reader).map_err(|e| format!("Invalid JSON format: {e}"))?;

        if import_data.entries.is_empty() {
            return Err("No entries found in import file".into());
        }

        Ok(import_data)
    }

    fn validate_entries(
        entries: Vec<ExportEntry>,
    ) -> (Vec<(ExportEntry, Vec<String>)>, Vec<String>) {
        let mut validated_entries = Vec::new();
        let mut validation_errors = Vec::new();
        let mut seen_names = HashSet::new();

        for mut entry in entries {
            if entry.name.trim().is_empty() || entry.name.len() > 128 {
                validation_errors.push("Entry with invalid or empty name".to_string());
                entry.password.zeroize_string();
                continue;
            }

            if entry.name.starts_with("__") {
                validation_errors.push(format!("Reserved name: {}", entry.name));
                entry.password.zeroize_string();
                continue;
            }

            if !seen_names.insert(entry.name.clone()) {
                validation_errors.push(format!("Duplicate entry in file: {}", entry.name));
                entry.password.zeroize_string();
                continue;
            }

            if let Err(e) = Password::length_check(&entry.password, MIN_ACCOUNT_PASSWORD_LENGTH) {
                validation_errors.push(format!("{}: {}", entry.name, e));
                entry.password.zeroize_string();
                continue;
            }

            if entry.password.len() > 128 {
                validation_errors.push(format!("{}: Password exceeds 128 chars", entry.name));
                entry.password.zeroize_string();
                continue;
            }

            if let Some(ref desc) = entry.description {
                if desc.len() > 500 {
                    validation_errors.push(format!("{}: Description too long", entry.name));
                    entry.password.zeroize_string();
                    continue;
                }

                if let Err(e) = Password::in_desc_check(&entry.password, desc) {
                    validation_errors.push(format!("{}: {}", entry.name, e));
                    entry.password.zeroize_string();
                    continue;
                }
            }

            let normalized_tags = TagValidator::normalize(&entry.tags);
            if let Err(e) = TagValidator::validate(&normalized_tags) {
                validation_errors.push(format!("{}: {}", entry.name, e));
                entry.password.zeroize_string();
                continue;
            }

            validated_entries.push((entry, normalized_tags));
        }

        (validated_entries, validation_errors)
    }

    fn apply_entries(
        storage: &Storage,
        crypto: &Crypto,
        validated_entries: Vec<(ExportEntry, Vec<String>)>,
        overwrite: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut imported_names = Vec::new();
        let mut original_entries: Vec<(String, PasswordEntry)> = Vec::new();

        let mut imported = 0;
        let mut skipped = 0;
        let mut failed = 0;

        for (mut entry, normalized_tags) in validated_entries {
            let exists = storage.entry_exists(&entry.name)?;

            if exists && !overwrite {
                eprintln!(
                    "Skipping '{}': already exists (use --overwrite to replace)",
                    entry.name
                );
                skipped += 1;
                entry.password.zeroize_string();
                continue;
            }

            if exists && let Ok(Some(original)) = storage.get_password(&entry.name) {
                original_entries.push((entry.name.clone(), original));
            }

            let tag_list = if normalized_tags.is_empty() {
                None
            } else {
                Some(normalized_tags.as_slice())
            };

            let secure_pass = SecureString::new(std::mem::take(&mut entry.password));

            match crypto.create_entry(
                secure_pass.as_bytes(),
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
                            Self::rollback_import(storage, &imported_names, &original_entries)?;
                            return Err(format!("Import failed, changes rolled back: {e}").into());
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
        println!("  Imported: {imported}");
        if skipped > 0 {
            println!("  Skipped: {skipped}");
        }
        if failed > 0 {
            println!("  Failed: {failed}");
        }

        Ok(())
    }

    fn rollback_import(
        storage: &Storage,
        imported_names: &[String],
        original_entries: &[(String, PasswordEntry)],
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

trait ZeroizeExt {
    fn zeroize_string(&mut self);
}

impl ZeroizeExt for String {
    fn zeroize_string(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}
