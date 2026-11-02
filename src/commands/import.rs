use crate::{
    core::{
        crypto::Crypto,
        interchange,
        limits::{MAX_ENTRIES, MAX_EXPORT_FILE_BYTES},
        storage::Storage,
        types::{ExportEntry, PasswordEntry},
    },
    modules::gateway::Gateway,
    ui::prompt::UserPrompt,
};
use std::{collections::HashSet, fs, path::Path};
use zeroize::{Zeroize, Zeroizing};

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
        Self::print_summary(&source);

        let (storage, crypto) = Gateway::login()?;
        let (validated_entries, validation_errors) = Self::validate_entries(source.entries);

        Self::print_validation_errors(&validation_errors);
        Self::apply_entries(&storage, &crypto, validated_entries, overwrite)
    }

    fn print_summary(source: &ImportSource) {
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
    }

    fn print_validation_errors(errors: &[String]) {
        if errors.is_empty() {
            return;
        }

        eprintln!("\nValidation errors:");
        for error in errors {
            eprintln!("  - {error}");
        }
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
            Ok(text) if interchange::is_csv(text) || !text.trim_start().starts_with('{') => {
                let entries = interchange::decode_csv(text)?;
                Ok(ImportSource {
                    format: "plaintext CSV",
                    version: None,
                    timestamp: None,
                    entries,
                })
            }
            _ => {
                let file = interchange::parse_encrypted(bytes)?;
                let passphrase = UserPrompt::password("Export passphrase: ")?;
                let data = interchange::open_encrypted(&passphrase, &file)?;

                Ok(ImportSource {
                    format: "encrypted export",
                    version: Some(data.version),
                    timestamp: Some(data.timestamp),
                    entries: data.entries,
                })
            }
        }
    }

    fn validate_entries(entries: Vec<ExportEntry>) -> (Vec<ExportEntry>, Vec<String>) {
        let mut validated_entries = Vec::new();
        let mut validation_errors = Vec::new();
        let mut seen_names = HashSet::new();

        for mut entry in entries {
            if !seen_names.insert(entry.name.clone()) {
                validation_errors.push(format!("Duplicate entry in file: {}", entry.name));
                continue;
            }

            match interchange::validate_import(&mut entry) {
                Ok(()) => validated_entries.push(entry),
                Err(message) => validation_errors.push(format!("{}: {message}", entry.name)),
            }
        }

        (validated_entries, validation_errors)
    }

    fn apply_entries(
        storage: &Storage,
        crypto: &Crypto,
        entries: Vec<ExportEntry>,
        overwrite: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut prepared: Vec<(String, PasswordEntry)> = Vec::new();
        let mut created: Vec<String> = Vec::new();
        let mut updated: Vec<String> = Vec::new();
        let mut skipped: usize = 0;
        let mut failed: usize = 0;

        for mut entry in entries {
            let exists = storage.entry_exists(&entry.name)?;

            if exists && !overwrite {
                eprintln!(
                    "Skipping '{}': already exists (use --overwrite to replace)",
                    entry.name
                );
                skipped += 1;
                continue;
            }

            let secure_password = Zeroizing::new(std::mem::take(&mut entry.password));
            let tag_list = (!entry.tags.is_empty()).then_some(entry.tags.as_slice());

            match crypto.create_entry(
                &entry.name,
                secure_password.as_bytes(),
                entry.description.as_deref(),
                tag_list,
            ) {
                Ok(stored) => {
                    if exists {
                        updated.push(entry.name.clone());
                    } else {
                        created.push(entry.name.clone());
                    }

                    prepared.push((entry.name.clone(), stored));
                }
                Err(error) => {
                    eprintln!("Error creating entry for '{}': {error}", entry.name);
                    failed += 1;
                }
            }
        }

        storage
            .put_entries(&prepared)
            .map_err(|error| format!("Import aborted, no changes were written: {error}"))?;

        for name in &created {
            println!("Imported: {name}");
        }

        for name in &updated {
            println!("Updated: {name}");
        }

        println!("\nImport completed:");
        println!("  Imported: {}", prepared.len());

        if skipped > 0 {
            println!("  Skipped: {skipped}");
        }

        if failed > 0 {
            println!("  Failed: {failed}");
        }

        Ok(())
    }
}
