use crate::{
    core::{
        crypto::Crypto,
        limits::MAX_ENTRIES,
        platform,
        storage::Storage,
        time::Time,
        types::{ExportEntry, PasswordEntry, SecureString},
    },
    modules::{export_format, gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
    utils::security::Security,
};
use rand::{RngCore, rngs::OsRng};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const WRITE_BUFFER_BYTES: usize = 64 * 1024;

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
    pub fn execute(csv: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;
        if csv {
            Security::confirmation(
                "This export writes every password in plain text to a CSV file.",
            )?;
        }

        let mut collected = Self::collect_entries(&storage, &crypto)?;
        if collected.entries.is_empty() {
            println!("No entries to export.");
            return Ok(());
        }
        collected.entries.sort_by(|a, b| a.name.cmp(&b.name));

        if csv {
            Self::export_csv(&collected.entries)
        } else {
            Self::export_encrypted(&collected.entries)
        }
    }

    fn export_encrypted(entries: &[ExportEntry]) -> Result<(), Box<dyn std::error::Error>> {
        let passphrase = Self::prompt_export_passphrase()?;
        let output = PathBuf::from(format!("cortex_export_{}.json", Self::random_token()));
        let bytes =
            export_format::encode_encrypted(&passphrase, entries, Time::current_timestamp())?;
        Self::write_atomically(&output, &bytes)?;
        eprintln!(
            "\nEncrypted export completed with {} entries",
            entries.len()
        );
        println!("\nExport saved to: {}", output.display());
        println!("The file is encrypted. Import it with the export passphrase.");
        Ok(())
    }

    fn export_csv(entries: &[ExportEntry]) -> Result<(), Box<dyn std::error::Error>> {
        let output = PathBuf::from(format!("cortex_export_{}.csv", Self::random_token()));
        let mut bytes = export_format::encode_csv(entries);
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

    fn prompt_export_passphrase() -> Result<SecureString, Box<dyn std::error::Error>> {
        println!("\nThe export is encrypted with a separate passphrase.");
        println!("You need this passphrase to import the file, and it cannot be recovered.");
        let passphrase = UserPrompt::password("Export passphrase: ")?;
        if let Err(message) = Password::security_check(passphrase.as_str()) {
            return Err(message.into());
        }
        let confirmation = UserPrompt::password("Confirm export passphrase: ")?;
        Password::match_check(passphrase.as_str(), confirmation.as_str())?;
        Ok(passphrase)
    }

    fn collect_entries(
        storage: &Storage,
        crypto: &Crypto,
    ) -> Result<Collected, Box<dyn std::error::Error>> {
        let mut collected = Collected {
            entries: Vec::new(),
        };
        let mut problems = Vec::new();
        let mut scanned: usize = 0;

        for item in storage.db.iter().take(MAX_ENTRIES + 1) {
            scanned += 1;
            match item {
                Ok((key, value)) => match Self::decode_entry(crypto, &key, &value) {
                    Ok(Some(entry)) => collected.entries.push(entry),
                    Ok(None) => {}
                    Err(message) => problems.push(message),
                },
                Err(error) => problems.push(format!("Database read error during export: {error}")),
            }
        }

        if scanned > MAX_ENTRIES {
            return Err(format!("Too many entries to export (limit is {MAX_ENTRIES})").into());
        }

        for entry in &mut collected.entries {
            if let Err(message) = export_format::normalize_and_validate(entry) {
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

    fn random_token() -> String {
        format!("{:016x}", OsRng.next_u64())
    }

    fn write_atomically(output: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
        Self::write_bytes(file, bytes)?;
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

    fn write_bytes(file: File, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut writer = BufWriter::with_capacity(WRITE_BUFFER_BYTES, file);
        writer.write_all(bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    }
}
