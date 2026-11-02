use crate::{
    core::{
        crypto::Crypto,
        interchange,
        limits::MAX_ENTRIES,
        platform,
        storage::{Storage, decode_value},
        types::{ExportEntry, PasswordEntry, decode_secret_text},
    },
    modules::{gateway::Gateway, security::Security},
};
use rand::RngExt;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

pub struct Export;

struct Collected {
    entries: Vec<ExportEntry>,
}

impl Drop for Collected {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.password.zeroize();
        }
    }
}

impl Export {
    pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;
        Security::confirmation("This export writes every password in plain text to a CSV file.")?;

        let mut collected = Self::collect_entries(&storage, &crypto)?;
        if collected.entries.is_empty() {
            println!("No entries to export.");
            return Ok(());
        }

        collected.entries.sort_by(|a, b| a.name.cmp(&b.name));
        Self::warn_about_rejected_entries(&collected.entries);

        Self::export_csv(&collected.entries)
    }

    fn warn_about_rejected_entries(entries: &[ExportEntry]) {
        let rejected = entries
            .iter()
            .filter(|entry| interchange::would_fail_import(entry))
            .count();
        if rejected == 0 {
            return;
        }

        let (entry_suffix, pronoun) = if rejected == 1 {
            ("y", "it")
        } else {
            ("ies", "them")
        };

        eprintln!(
            "Warning: {rejected} entr{entry_suffix} would be rejected on import (short password or control characters). Update {pronoun} with edit before relying on this export."
        );
    }

    fn export_csv(entries: &[ExportEntry]) -> Result<(), Box<dyn std::error::Error>> {
        let output = PathBuf::from(format!("cortex_export_{}.csv", Self::random_token()));

        let mut bytes = interchange::encode_csv(entries)?;
        let written = Self::write_atomically(&output, &bytes);

        bytes.zeroize();
        written?;

        eprintln!(
            "\nPlaintext CSV export completed with {} entries",
            entries.len()
        );

        println!("\nExport saved to: {}", output.display());
        println!(
            "The file is NOT encrypted. Keep it safe and delete it when you no longer need it."
        );
        Ok(())
    }

    fn collect_entries(
        storage: &Storage,
        crypto: &Crypto,
    ) -> Result<Collected, Box<dyn std::error::Error>> {
        let records = storage.records()?;
        if records.len() > MAX_ENTRIES {
            return Err(format!("Too many entries to export (limit is {MAX_ENTRIES})").into());
        }

        let mut collected = Collected {
            entries: Vec::new(),
        };

        let mut problems = Vec::new();

        for (key, value) in &records {
            match Self::decode_entry(crypto, key, value) {
                Ok(Some(entry)) => collected.entries.push(entry),
                Ok(None) => {}
                Err(message) => problems.push(message),
            }
        }

        for entry in &mut collected.entries {
            if let Err(message) = interchange::validate_stored(entry) {
                problems.push(format!("{}: {message}", entry.name));
            }
        }

        if !problems.is_empty() {
            for problem in &problems {
                eprintln!("  - {problem}");
            }

            return Err(format!(
                "Export aborted: {} problem(s) found, no file was written",
                problems.len()
            )
            .into());
        }

        Ok(collected)
    }

    fn decode_entry(
        crypto: &Crypto,
        key: &[u8],
        value: &[u8],
    ) -> Result<Option<ExportEntry>, String> {
        let name = String::from_utf8_lossy(key).into_owned();
        if name.starts_with("__") {
            return Ok(None);
        }

        let entry: PasswordEntry = decode_value(value)
            .map_err(|error| format!("Failed to deserialize entry '{name}': {error}"))?;
        let password_bytes = crypto
            .decrypt_entry(&name, &entry)
            .map_err(|error| format!("Failed to decrypt entry '{name}': {error}"))?;

        let password = decode_secret_text(password_bytes)
            .map_err(|error| format!("Failed to decrypt entry '{name}': {error}"))?;
        let description = crypto
            .decrypt_description(&name, &entry)
            .map_err(|error| format!("Failed to decrypt description of '{name}': {error}"))?;

        let tags = crypto
            .decrypt_tags(&name, &entry)
            .map_err(|error| format!("Failed to decrypt tags of '{name}': {error}"))?;

        Ok(Some(ExportEntry {
            name,
            password,
            description,
            tags,
        }))
    }

    fn random_token() -> String {
        format!("{:016x}", rand::rng().random::<u64>())
    }

    fn write_atomically(output: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::current_dir()?;
        let mut temp = tempfile::NamedTempFile::new_in(&directory)?;

        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;

        platform::restrict_to_owner(temp.path())?;

        temp.persist_noclobber(output).map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                format!("File already exists: {}", output.display())
            } else {
                format!(
                    "Failed to publish export {}: {}",
                    output.display(),
                    error.error
                )
            }
        })?;

        Ok(())
    }
}
