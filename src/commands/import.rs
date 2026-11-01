use crate::{
    core::{
        crypto::Crypto,
        limits::{MAX_ENTRIES, MAX_EXPORT_FILE_BYTES},
        storage::Storage,
        types::{ExportEntry, PasswordEntry, SecureString},
    },
    modules::{export_format, gateway::Gateway},
    ui::prompt::UserPrompt,
};
use std::{collections::HashSet, fs, path::Path};
use zeroize::Zeroize;

pub struct Import;

struct ImportSource {
    format: &'static str,
    version: Option<String>,
    timestamp: Option<u64>,
    entries: Vec<ExportEntry>,
}

impl Import {
    pub fn execute(file_path: &str, overwrite: bool) -> Result<(), Box<dyn std::error::Error>> {
        let source = Self::read_file(file_path)?;

        println!("\nImport Summary:");
        println!("  Format: {}", source.format);
        if let Some(version) = &source.version {
            println!("  Version: {version}");
        }
        if let Some(timestamp) = source.timestamp {
            println!("  Timestamp: {timestamp}");
        }
        println!("  Total entries: {}", source.entries.len());
        println!();

        let (storage, crypto) = Gateway::login()?;
        let (validated_entries, validation_errors) = Self::validate_entries(source.entries);

        if !validation_errors.is_empty() {
            eprintln!("\nValidation errors:");
            for error in &validation_errors {
                eprintln!("  - {error}");
            }
        }

        Self::apply_entries(&storage, &crypto, validated_entries, overwrite)
    }

    fn read_file(file_path: &str) -> Result<ImportSource, Box<dyn std::error::Error>> {
        if file_path.trim().is_empty() {
            return Err("File path cannot be empty".into());
        }

        let path = Path::new(file_path);
        let size = fs::metadata(path)
            .map_err(|_| format!("File not found: {file_path}"))?
            .len();
        if size > MAX_EXPORT_FILE_BYTES {
            return Err("Import file is too large".into());
        }

        let mut bytes =
            fs::read(path).map_err(|error| format!("Failed to read {file_path}: {error}"))?;
        let parsed = Self::parse_import(&bytes);
        bytes.zeroize();
        let source = parsed?;

        if source.entries.is_empty() {
            return Err("No entries found in import file".into());
        }
        if source.entries.len() > MAX_ENTRIES {
            return Err(format!("Too many entries to import (limit is {MAX_ENTRIES})").into());
        }
        Ok(source)
    }

    fn parse_import(bytes: &[u8]) -> Result<ImportSource, Box<dyn std::error::Error>> {
        match std::str::from_utf8(bytes) {
            Ok(text) if export_format::is_csv(text) || !text.trim_start().starts_with('{') => {
                let entries = export_format::decode_csv(text)?;
                Ok(ImportSource {
                    format: "plaintext CSV",
                    version: None,
                    timestamp: None,
                    entries,
                })
            }
            _ => {
                let file = export_format::parse_encrypted(bytes)?;
                let passphrase = UserPrompt::password("Export passphrase: ")?;
                let data = export_format::open_encrypted(&passphrase, &file)?;
                Ok(ImportSource {
                    format: "encrypted export",
                    version: Some(data.version),
                    timestamp: Some(data.timestamp),
                    entries: data.entries,
                })
            }
        }
    }

    fn validate_entries(
        entries: Vec<ExportEntry>,
    ) -> (Vec<(ExportEntry, Vec<String>)>, Vec<String>) {
        let mut validated_entries = Vec::new();
        let mut validation_errors = Vec::new();
        let mut seen_names = HashSet::new();

        for mut entry in entries {
            if !seen_names.insert(entry.name.clone()) {
                validation_errors.push(format!("Duplicate entry in file: {}", entry.name));
                entry.password.zeroize_string();
                continue;
            }

            match export_format::normalize_and_validate(&mut entry) {
                Ok(()) => {
                    let tags = entry.tags.clone();
                    validated_entries.push((entry, tags));
                }
                Err(message) => {
                    validation_errors.push(format!("{}: {message}", entry.name));
                    entry.password.zeroize_string();
                }
            }
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
            let exists = match storage.entry_exists(&entry.name) {
                Ok(exists) => exists,
                Err(error) => {
                    return Self::fail_import(storage, &imported_names, &original_entries, error);
                }
            };

            if exists && !overwrite {
                eprintln!(
                    "Skipping '{}': already exists (use --overwrite to replace)",
                    entry.name
                );
                skipped += 1;
                entry.password.zeroize_string();
                continue;
            }

            if exists {
                match storage.get_password(&entry.name) {
                    Ok(Some(original)) => original_entries.push((entry.name.clone(), original)),
                    Ok(None) => {
                        return Self::fail_import(
                            storage,
                            &imported_names,
                            &original_entries,
                            format!("Entry '{}' disappeared before overwrite", entry.name),
                        );
                    }
                    Err(error) => {
                        return Self::fail_import(
                            storage,
                            &imported_names,
                            &original_entries,
                            error,
                        );
                    }
                }
            }

            let tag_list = if normalized_tags.is_empty() {
                None
            } else {
                Some(normalized_tags.as_slice())
            };

            let secure_pass = SecureString::new(std::mem::take(&mut entry.password));

            match crypto.create_entry(
                &entry.name,
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
                        Err(error) => {
                            eprintln!("Error importing '{}': {error}", entry.name);
                            return Self::fail_import(
                                storage,
                                &imported_names,
                                &original_entries,
                                error,
                            );
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

    fn fail_import(
        storage: &Storage,
        imported_names: &[String],
        original_entries: &[(String, PasswordEntry)],
        error: impl std::fmt::Display,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(rollback_error) =
            Self::rollback_import(storage, imported_names, original_entries)
        {
            return Err(
                format!("Import failed: {error}. Rollback also failed: {rollback_error}").into(),
            );
        }
        Err(format!("Import failed, changes rolled back: {error}").into())
    }

    fn rollback_import(
        storage: &Storage,
        imported_names: &[String],
        original_entries: &[(String, PasswordEntry)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("\nRolling back changes...");
        let mut rollback_error: Option<Box<dyn std::error::Error>> = None;

        for name in imported_names {
            if let Err(error) = storage.delete_password(name) {
                eprintln!("Rollback failed to delete '{name}': {error}");
                if rollback_error.is_none() {
                    rollback_error = Some(error);
                }
            }
        }

        for (name, entry) in original_entries {
            if let Err(error) = storage.edit_password(name, entry) {
                eprintln!("Rollback failed to restore '{name}': {error}");
                if rollback_error.is_none() {
                    rollback_error = Some(error);
                }
            }
        }

        storage.flush()?;
        if let Some(error) = rollback_error {
            return Err(error);
        }
        eprintln!("Rollback completed.");
        Ok(())
    }
}

trait ZeroizeExt {
    fn zeroize_string(&mut self);
}

impl ZeroizeExt for String {
    fn zeroize_string(&mut self) {
        self.zeroize();
    }
}
