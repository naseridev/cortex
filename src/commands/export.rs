use crate::{
    core::{
        crypto::Crypto,
        limits::MAX_ENTRIES,
        storage::Storage,
        time::Time,
        types::{ExportEntry, PasswordEntry, SecureString},
    },
    modules::gateway::Gateway,
    platform,
    utils::security::Security,
};
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const EXPORT_FORMAT_VERSION: &str = "3.0.0";
const TEMPLATE_FILE_NAME: &str = "cortex_template.json";
const WRITE_BUFFER_BYTES: usize = 64 * 1024;
const EXPORT_WARNING: &str = "I understand this exports passwords in plain text";

pub struct Export;

#[derive(Serialize)]
struct ExportDocument<'a> {
    version: &'static str,
    timestamp: u64,
    entries: &'a [ExportEntry],
}

struct Collected {
    entries: Vec<ExportEntry>,
    failed: usize,
}

impl Drop for Collected {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.password.zeroize();
        }
    }
}

struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl TempFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => eprintln!(
                "Warning: could not remove temporary file {}: {error}. Delete it manually.",
                self.path.display()
            ),
        }
    }
}

impl Export {
    pub fn execute(template: bool) -> Result<(), Box<dyn std::error::Error>> {
        if template {
            return Self::export_template();
        }

        let (storage, crypto) = Gateway::login()?;

        Self::print_plaintext_warning();
        Security::confirmation(EXPORT_WARNING)?;

        let output = PathBuf::from(format!(
            "cortex_export_{:x}.json",
            Time::current_timestamp()
        ));

        let mut collected = Self::collect_entries(&storage, &crypto)?;
        if collected.entries.is_empty() {
            println!("No entries were successfully exported.");
            return Ok(());
        }

        collected.entries.sort_by(|a, b| a.name.cmp(&b.name));
        Self::write_atomically(&output, &collected.entries)?;
        Self::report_success(collected.entries.len(), collected.failed, &output);

        Ok(())
    }

    fn print_plaintext_warning() {
        println!("\nThis will export ALL passwords in PLAIN TEXT format!");
        println!("Anyone with access to this file can read your passwords.");
    }

    fn collect_entries(
        storage: &Storage,
        crypto: &Crypto,
    ) -> Result<Collected, Box<dyn std::error::Error>> {
        let mut collected = Collected {
            entries: Vec::new(),
            failed: 0,
        };
        let mut scanned: usize = 0;

        for item in storage.db.iter().take(MAX_ENTRIES + 1) {
            scanned += 1;
            match item {
                Ok((key, value)) => match Self::decode_entry(crypto, &key, &value) {
                    Ok(Some(entry)) => collected.entries.push(entry),
                    Ok(None) => {}
                    Err(message) => {
                        eprintln!("{message}");
                        collected.failed += 1;
                    }
                },
                Err(error) => {
                    eprintln!("Database read error during export: {error}");
                    collected.failed += 1;
                }
            }
        }

        if scanned > MAX_ENTRIES {
            return Err(format!("Too many entries to export (limit is {MAX_ENTRIES})").into());
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

        let entry: PasswordEntry = bincode::deserialize(value)
            .map_err(|error| format!("Failed to deserialize entry '{name}': {error}"))?;
        let password = Self::decrypt_password(crypto, &name, &entry)
            .map_err(|error| format!("Failed to decrypt entry '{name}': {error}"))?;
        let description = crypto
            .decrypt_description(&name, &entry)
            .map_err(|error| format!("Failed to decrypt description of '{name}': {error}"))?;
        let tags = crypto
            .decrypt_tags(&name, &entry)
            .map_err(|error| format!("Failed to decrypt tags of '{name}': {error}"))?;

        Ok(Some(ExportEntry {
            name,
            password: password.as_str().to_string(),
            description,
            tags,
        }))
    }

    fn decrypt_password(
        crypto: &Crypto,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<SecureString, Box<dyn std::error::Error>> {
        let bytes = crypto.decrypt_entry(name, entry)?;
        match String::from_utf8(bytes) {
            Ok(password) => Ok(SecureString::new(password)),
            Err(error) => {
                let mut raw = error.into_bytes();
                raw.zeroize();
                Err("Password is not valid UTF-8".into())
            }
        }
    }

    fn write_atomically(
        output: &Path,
        entries: &[ExportEntry],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp_path = PathBuf::from(format!("{}.tmp", output.display()));
        let file = platform::create_private_file(&temp_path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                format!(
                    "Temporary file already exists, remove it and retry: {}",
                    temp_path.display()
                )
            } else {
                error.to_string()
            }
        })?;
        let mut temp = TempFile::new(temp_path);
        Self::write_json(file, entries)?;
        fs::hard_link(&temp.path, output).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                format!("File already exists: {}", output.display())
            } else {
                format!("Failed to publish export {}: {error}", output.display())
            }
        })?;
        temp.disarm();
        fs::remove_file(&temp.path)?;
        Ok(())
    }

    fn write_json(file: File, entries: &[ExportEntry]) -> Result<(), Box<dyn std::error::Error>> {
        let document = ExportDocument {
            version: EXPORT_FORMAT_VERSION,
            timestamp: Time::current_timestamp(),
            entries,
        };
        let mut writer = BufWriter::with_capacity(WRITE_BUFFER_BYTES, file);
        serde_json::to_writer_pretty(&mut writer, &document)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    }

    fn report_success(exported: usize, failed: usize, output: &Path) {
        if failed > 0 {
            eprintln!("\nExport completed with {exported} successful and {failed} failed entries");
        } else {
            eprintln!("\nExport completed successfully with {exported} entries");
        }
        println!("\nExport saved to: {}", output.display());
        println!("\nREMEMBER: This file contains UNENCRYPTED passwords!");
        println!("Secure or delete it immediately after use.");
    }

    fn export_template() -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from(TEMPLATE_FILE_NAME);
        let entries = Self::template_entries();
        let file = platform::create_private_file(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                format!("File already exists: {}", path.display())
            } else {
                error.to_string()
            }
        })?;
        Self::write_json(file, &entries)?;

        println!("Template exported to {}", path.display());
        println!("\nYou can use this template structure to import passwords.");
        Ok(())
    }

    fn template_entries() -> Vec<ExportEntry> {
        vec![
            ExportEntry {
                name: "heisenberg".to_string(),
                password: "1AmTh3D4ng3r!".to_string(),
                description: Some("Say my name - I am the one who knocks".to_string()),
                tags: vec!["work".to_string(), "critical".to_string()],
            },
            ExportEntry {
                name: "los-pollos".to_string(),
                password: "Gustu5Fr!ng2024".to_string(),
                description: Some("A man provides for his family".to_string()),
                tags: vec!["business".to_string(), "finance".to_string()],
            },
            ExportEntry {
                name: "saul-goodman".to_string(),
                password: "B3tt3rC4llS4ul!".to_string(),
                description: Some(
                    "Did you know you have rights? Constitution says you do".to_string(),
                ),
                tags: vec!["legal".to_string(), "contacts".to_string()],
            },
        ]
    }
}
