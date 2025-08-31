use blake3::Hasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use std::io::{self, BufWriter, Write};
use sysinfo::{CpuExt, System, SystemExt};
use zeroize::Zeroize;

const INIT_MARKER: &str = "__init__";
const TEST_DATA: &[u8] = b"cortex_secure_init_marker";
const HARDWARE_SALT: &[u8] = b"classified_eyes_only";
const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "Keep your passwords safe",
    version = "1.0.0",
    author = "Nima Naseri <nerdnull@proton.me>"
)]
#[command(long_about = "A no-nonsense password manager using hardware-backed key derivation.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Initialize a new password database with master password")]
    Init,

    #[command(about = "Create a new password entry")]
    Create {
        #[arg(help = "Name/identifier for the password entry")]
        name: String,
    },

    #[command(about = "Retrieve a password entry")]
    Get {
        #[arg(help = "Name of the password entry to retrieve")]
        name: String,
    },

    #[command(about = "List all stored password entries")]
    List,

    #[command(about = "Delete a password entry")]
    Delete {
        #[arg(help = "Name of the password entry to delete")]
        name: String,
    },

    #[command(about = "Edit password and description for existing entry")]
    Edit {
        #[arg(help = "Name of the password entry to edit")]
        name: String,
    },

    #[command(about = "Search password entries by name or description")]
    Find {
        #[arg(help = "Search pattern (supports regex)")]
        pattern: String,

        #[arg(short, long, help = "Case insensitive search")]
        ignore_case: bool,

        #[arg(short, long, help = "Search only in names (not descriptions)")]
        names_only: bool,
    },

    #[command(about = "Export all passwords to plain text file")]
    Export,

    #[command(about = "Reset the master password")]
    Reset,

    #[command(about = "Permanently purge the entire password database")]
    Purge,

    #[command(about = "Generate strong passwords")]
    Pass {
        #[arg(short = 'e', long, help = "Password length", default_value = "16")]
        length: usize,

        #[arg(
            short = 'c',
            long,
            help = "Number of passwords to generate",
            default_value = "1"
        )]
        count: usize,

        #[arg(
            short = 'u',
            long,
            help = "Include uppercase letters",
            default_value = "true"
        )]
        uppercase: bool,

        #[arg(
            short = 'l',
            long,
            help = "Include lowercase letters",
            default_value = "true"
        )]
        lowercase: bool,

        #[arg(short = 'd', long, help = "Include digits", default_value = "true")]
        digits: bool,

        #[arg(
            short = 's',
            long,
            help = "Include special characters",
            default_value = "true"
        )]
        special: bool,

        #[arg(
            short = 'n',
            long,
            help = "Exclude ambiguous characters (0, O, l, 1, etc.)"
        )]
        no_ambiguous: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct ExportData {
    version: String,
    timestamp: u64,
    entries: Vec<ExportEntry>,
}

#[derive(Serialize, Deserialize)]
struct ExportEntry {
    name: String,
    password: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    encrypted_password: Vec<u8>,
    encrypted_description: Option<Vec<u8>>,
    nonce: [u8; 12],
    desc_nonce: Option<[u8; 12]>,
    timestamp: u64,
}

struct SecureString(String);

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecureString {
    fn new(s: String) -> Self {
        Self(s)
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

struct Cortex {
    db: sled::Db,
    cipher: ChaCha20Poly1305,
}

impl Cortex {
    fn new(master_password: &SecureString) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path();
        let db = sled::open(&db_path)?;
        let cipher = ChaCha20Poly1305::new(&Self::derive_key(master_password.as_bytes()));

        Ok(Self { db, cipher })
    }

    fn init_db(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entry = self.create_entry(TEST_DATA, None)?;
        self.db.insert(INIT_MARKER, bincode::serialize(&entry)?)?;
        self.db.flush()?;

        Ok(())
    }

    fn verify_master_password(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let result = match self.db.get(INIT_MARKER)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)?;
                self.decrypt_entry(&entry)
                    .map(|d| d == TEST_DATA)
                    .unwrap_or(false)
            }
            None => false,
        };

        Ok(result)
    }

    fn create_entry(
        &self,
        data: &[u8],
        description: Option<&str>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];

        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| "Encryption failed")?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let mut desc_nonce_bytes = [0u8; 12];

            OsRng.fill_bytes(&mut desc_nonce_bytes);
            let desc_nonce = Nonce::from_slice(&desc_nonce_bytes);

            let encrypted_desc = self
                .cipher
                .encrypt(desc_nonce, desc.as_bytes())
                .map_err(|_| "Description encryption failed")?;

            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        Ok(PasswordEntry {
            encrypted_password: encrypted,
            encrypted_description,
            nonce: nonce_bytes,
            desc_nonce,
            timestamp: Self::current_timestamp(),
        })
    }

    fn decrypt_entry(&self, entry: &PasswordEntry) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let nonce = Nonce::from_slice(&entry.nonce);
        self.cipher
            .decrypt(nonce, entry.encrypted_password.as_ref())
            .map_err(|_| "Decryption failed".into())
    }

    fn decrypt_description(
        &self,
        entry: &PasswordEntry,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        if let (Some(encrypted_desc), Some(desc_nonce)) =
            (&entry.encrypted_description, &entry.desc_nonce)
        {
            let nonce = Nonce::from_slice(desc_nonce);
            let decrypted = self
                .cipher
                .decrypt(nonce, encrypted_desc.as_ref())
                .map_err(|_| "Description decryption failed")?;

            Ok(Some(String::from_utf8(decrypted)?))
        } else {
            Ok(None)
        }
    }

    fn create_password(
        &self,
        name: &str,
        password: &SecureString,
        description: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if self.db.get(name)?.is_some() {
            return Ok(false);
        }

        let entry = self.create_entry(password.as_bytes(), description)?;
        self.db.insert(name, bincode::serialize(&entry)?)?;
        self.db.flush()?;

        Ok(true)
    }

    fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<(SecureString, Option<String>)>, Box<dyn std::error::Error>> {
        match self.db.get(name)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)?;
                let decrypted = self.decrypt_entry(&entry)?;
                let password = String::from_utf8(decrypted)?;
                let description = self.decrypt_description(&entry)?;
                Ok(Some((SecureString::new(password), description)))
            }
            None => Ok(None),
        }
    }

    fn list_entries(&self) -> Result<Vec<(String, Option<String>)>, Box<dyn std::error::Error>> {
        let mut entries: Vec<(String, Option<String>)> = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())?;

            if !key_str.starts_with("__") {
                let entry: PasswordEntry = bincode::deserialize(&value)?;
                let description = self.decrypt_description(&entry)?;
                entries.push((key_str, description));
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    fn delete_password(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(false);
        }

        match self.db.remove(name)? {
            Some(_) => {
                self.db.flush()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn edit_password(
        &self,
        name: &str,
        new_password: &SecureString,
        new_description: Option<&str>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") || self.db.get(name)?.is_none() {
            return Ok(false);
        }

        let entry = self.create_entry(new_password.as_bytes(), new_description)?;
        self.db.insert(name, bincode::serialize(&entry)?)?;
        self.db.flush()?;

        Ok(true)
    }

    fn search_entries(
        &self,
        pattern: &str,
        ignore_case: bool,
        names_only: bool,
    ) -> Result<Vec<(String, Option<String>, bool, bool)>, Box<dyn std::error::Error>> {
        if pattern.trim().is_empty() {
            return Err("Search pattern cannot be empty".into());
        }

        if pattern.len() > 100 {
            return Err("Search pattern too long (max 100 chars)".into());
        }

        let regex_flags = if ignore_case { "(?i)" } else { "" };
        let full_pattern = format!("{}{}", regex_flags, regex::escape(pattern));
        let re = Regex::new(&full_pattern).map_err(|e| format!("Invalid search pattern: {}", e))?;

        let mut results = Vec::new();
        let mut processed = 0;

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key).to_string();

            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;
            if processed > 10000 {
                return Err("Too many entries to search".into());
            }

            let name_match = re.is_match(&key_str);

            let (description, desc_match) = if names_only {
                (None, false)
            } else if name_match {
                let entry: PasswordEntry = bincode::deserialize(&value)?;
                let desc = self.decrypt_description(&entry).unwrap_or(None);
                (desc, false)
            } else {
                let entry: PasswordEntry = bincode::deserialize(&value)?;
                match self.decrypt_description(&entry) {
                    Ok(Some(desc)) => {
                        let desc_match = re.is_match(&desc);
                        (Some(desc), desc_match)
                    }
                    Ok(None) => (None, false),
                    Err(_) => continue,
                }
            };

            if name_match || desc_match {
                results.push((key_str, description, name_match, desc_match));
            }
        }

        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(results)
    }

    fn reset_master_password(
        &self,
        new_password: &SecureString,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = self.collect_all_entries()?;
        let new_cipher = ChaCha20Poly1305::new(&Self::derive_key(new_password.as_bytes()));

        for (name, password, description) in &entries {
            let entry = Self::encrypt_with_cipher(
                &new_cipher,
                password.as_bytes(),
                description.as_deref(),
            )?;
            self.db.insert(name, bincode::serialize(&entry)?)?;
        }

        let test_entry = Self::encrypt_with_cipher(&new_cipher, TEST_DATA, None)?;
        self.db
            .insert(INIT_MARKER, bincode::serialize(&test_entry)?)?;
        self.db.flush()?;

        Ok(())
    }

    fn collect_all_entries(
        &self,
    ) -> Result<Vec<(String, SecureString, Option<String>)>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())?;

            if !key_str.starts_with("__") {
                let entry: PasswordEntry = bincode::deserialize(&value)?;
                let decrypted = self.decrypt_entry(&entry)?;
                let password = String::from_utf8(decrypted)?;
                let description = self.decrypt_description(&entry)?;
                entries.push((key_str, SecureString::new(password), description));
            }
        }

        Ok(entries)
    }

    fn encrypt_with_cipher(
        cipher: &ChaCha20Poly1305,
        data: &[u8],
        description: Option<&str>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];

        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|_| "Encryption failed")?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let mut desc_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut desc_nonce_bytes);
            let desc_nonce = Nonce::from_slice(&desc_nonce_bytes);

            let encrypted_desc = cipher
                .encrypt(desc_nonce, desc.as_bytes())
                .map_err(|_| "Description encryption failed")?;

            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        Ok(PasswordEntry {
            encrypted_password: encrypted,
            encrypted_description,
            nonce: nonce_bytes,
            desc_nonce,
            timestamp: Self::current_timestamp(),
        })
    }

    fn purge_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.db.clear()?;
        self.db.flush()?;

        let db_path = Self::get_db_path();
        if db_path.exists() {
            if let Some(parent) = db_path.parent() {
                std::fs::remove_dir_all(parent)?;
            }
        }

        Ok(())
    }

    fn derive_key(password: &[u8]) -> Key {
        let hardware_id = Self::get_hardware_id();
        let mut hasher = Hasher::new();

        hasher.update(password);
        hasher.update(&hardware_id);

        let hash = hasher.finalize();
        let key_bytes: [u8; 32] = hash.as_bytes()[..32].try_into().unwrap();
        Key::from(key_bytes)
    }

    fn get_hardware_id() -> Vec<u8> {
        let mut hasher = Hasher::new();
        let mut sys = System::new_all();

        sys.refresh_all();

        if let Some(cpu) = sys.cpus().first() {
            hasher.update(cpu.brand().as_bytes());
        }

        hasher.update(HARDWARE_SALT);
        hasher.finalize().as_bytes().to_vec()
    }

    fn get_db_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("cortex");

        std::fs::create_dir_all(&path).ok();
        path.push("passwords.db");
        path
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn export_passwords(&self, output_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::create(output_path)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        writeln!(writer, "# Cortex Password Export\n")?;

        let mut processed = 0;
        let mut failed = 0;

        for item in self.db.iter() {
            let (key, value) = match item {
                Ok((k, v)) => (k, v),
                Err(_) => continue,
            };

            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;

            if processed % 1000 == 0 {
                writer.flush()?;
                eprint!("\rProcessed {} entries...", processed);
                io::stderr().flush()?;
            }

            match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => match self.decrypt_and_write_entry(&mut writer, &key_str, &entry) {
                    Ok(_) => {}
                    Err(_) => failed += 1,
                },
                Err(_) => failed += 1,
            }
        }

        writer.flush()?;

        if processed >= 1000 {
            eprintln!("\rCompleted {} entries.", processed);
        }

        if failed > 0 {
            eprintln!("Warning: {} entries failed to decrypt", failed);
        }

        Ok(())
    }

    fn decrypt_and_write_entry(
        &self,
        writer: &mut BufWriter<std::fs::File>,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let decrypted_bytes = self.decrypt_entry(entry)?;
        let password = String::from_utf8(decrypted_bytes)?;

        let description = self.decrypt_description(entry)?;

        writeln!(writer, "Name: {}", name)?;
        writeln!(writer, "Password: {}", password)?;

        if let Some(desc) = description {
            writeln!(writer, "Description: {}", desc)?;
        }

        writeln!(writer)?;

        drop(password);

        Ok(())
    }
}

struct Handler;

impl Handler {
    fn handle_init() -> Result<(), Box<dyn std::error::Error>> {
        let db_path = Cortex::get_db_path();

        if db_path.exists() {
            eprintln!("Database exists. Use 'reset' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;

        if let Err(msg) = Utils::validate_password_security(master_password.as_str()) {
            eprintln!("Error: {}", msg);
            process::exit(1);
        }

        let confirm_password = UserPrompt::password("Confirm password: ")?;

        if master_password.as_str() != confirm_password.as_str() {
            return Err("Password mismatch".into());
        }

        let guard = Cortex::new(&master_password)?;
        guard.init_db()?;

        println!("Initialized.");

        Ok(())
    }

    fn handle_create(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        if guard.db.get(&name)?.is_some() {
            eprintln!(
                "Error: Account '{}' already exists. Use 'edit' to update or choose a different name.",
                name
            );
            process::exit(1);
        }

        let password = UserPrompt::text("Password to store: ")?;

        if password.len() < MIN_ACCOUNT_PASSWORD_LENGTH {
            return Err(format!(
                "Password must be at least {} characters",
                MIN_ACCOUNT_PASSWORD_LENGTH
            )
            .into());
        }

        let confirm_password = UserPrompt::text("Confirm password: ")?;

        if password.as_str() != confirm_password.as_str() {
            return Err("Password mismatch".into());
        }

        let description_input = UserPrompt::text("Description (optional): ")?;
        let description = if description_input.is_empty() {
            None
        } else if Utils::password_in_desc_found(password.as_str(), &description_input) {
            eprintln!("Error: Description cannot contain the password or parts of it.");
            process::exit(1);
        } else {
            Some(description_input.as_str())
        };

        if guard.create_password(&name, &SecureString::new(password), description)? {
            println!("Created '{}'.", name);
        }

        Ok(())
    }

    fn handle_get(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        match guard.get_password(&name)? {
            Some((password, description)) => {
                println!();
                println!("{}: {}", name, password.as_str());
                if let Some(desc) = description {
                    println!("Description: {}", desc);
                }
            }
            None => println!("Not found: {}", name),
        }

        Ok(())
    }

    fn handle_list() -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        let entries = guard.list_entries()?;

        if entries.is_empty() {
            println!("No entries");
        } else {
            for (name, description) in entries {
                println!();
                println!("Entry: {}", name);
                if let Some(desc) = &description {
                    println!("Description: {}", desc);
                }
            }
        }

        Ok(())
    }

    fn handle_delete(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        if guard.delete_password(&name)? {
            println!("Deleted '{}'.", name);
        } else {
            println!("Not found: {}", name);
        }

        Ok(())
    }

    fn handle_edit(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        let current_entry = match guard.get_password(&name)? {
            Some((password, description)) => (password, description),
            None => return Err(format!("Entry '{}' does not exist.", name).into()),
        };

        let new_password_input = UserPrompt::text("New password (Enter to keep current): ")?;
        let new_password = if new_password_input.is_empty() {
            current_entry.0.as_str().to_string()
        } else {
            if new_password_input.len() < MIN_ACCOUNT_PASSWORD_LENGTH {
                return Err(format!(
                    "Password must be at least {} characters",
                    MIN_ACCOUNT_PASSWORD_LENGTH
                )
                .into());
            }

            let confirm_password = UserPrompt::text("Confirm new password: ")?;
            if new_password_input != confirm_password {
                return Err("Password mismatch".into());
            }

            new_password_input
        };

        let description_input = UserPrompt::text("New description (Enter to keep current): ")?;
        let description = if description_input.is_empty() {
            current_entry.1.as_deref()
        } else {
            if Utils::password_in_desc_found(&new_password, &description_input) {
                eprintln!("Error: Description cannot contain the password or parts of it.");
                process::exit(1);
            }

            Some(description_input.as_str())
        };

        if new_password == current_entry.0.as_str() && description == current_entry.1.as_deref() {
            println!("No changes made to '{}'.", name);
            return Ok(());
        }

        if guard.edit_password(&name, &SecureString::new(new_password), description)? {
            println!("Edited for '{}'.", name);
        }

        Ok(())
    }

    fn handle_find(
        pattern: String,
        ignore_case: bool,
        names_only: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        if pattern.trim().is_empty() {
            eprintln!("Error: Search pattern cannot be empty.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        match guard.search_entries(&pattern, ignore_case, names_only) {
            Ok(results) => {
                if results.is_empty() {
                    println!("No matches found for: {}", pattern);
                    return Ok(());
                }

                println!();
                println!("Found {} match(es) for: {}", results.len(), pattern);

                if results.len() > 20 {
                    println!("(Showing first 20 results)");
                }

                println!();

                for (name, description, name_match, desc_match) in results.iter().take(20) {
                    println!("Entry: {}", name);

                    if *name_match && *desc_match {
                        println!("  >> Matches: name and description");
                    } else if *name_match {
                        println!("  >> Matches: name");
                    } else if *desc_match {
                        println!("  >> Matches: description");
                    }

                    if let Some(desc) = description {
                        let display_desc = if desc.len() > 60 {
                            format!("{}...", &desc[..57])
                        } else {
                            desc.clone()
                        };
                        println!("  Description: {}", display_desc);
                    }

                    println!();
                }

                if results.len() > 20 {
                    println!("... and {} more results", results.len() - 20);
                }
            }
            Err(e) => {
                eprintln!("Search failed: {}", e);
                process::exit(1);
            }
        }

        Ok(())
    }

    fn handle_export() -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        let (puzzle, answer) = Utils::generate_math_puzzle();

        println!();
        println!("WARNING: This will export all passwords in plain text format.");
        println!("Solve this equation to confirm: {}", puzzle);
        println!();

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        if user_num != answer {
            println!("Wrong answer. Export cancelled.");
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let filename = format!("cortex_export_{:x}.dat", timestamp);
        let output_path = PathBuf::from(filename);

        match guard.export_passwords(&output_path) {
            Ok(_) => println!("Export completed to {}", output_path.display()),
            Err(e) => {
                let _ = std::fs::remove_file(&output_path);
                return Err(e);
            }
        }

        Ok(())
    }

    fn handle_reset() -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let old_password = UserPrompt::password("Current master password: ")?;
        let guard = Cortex::new(&old_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        let new_password = UserPrompt::password("New master password: ")?;

        if let Err(msg) = Utils::validate_password_security(new_password.as_str()) {
            eprintln!("Error: {}", msg);
            process::exit(1);
        }

        let confirm_password = UserPrompt::password("Confirm new password: ")?;

        if new_password.as_str() != confirm_password.as_str() {
            return Err("Password mismatch".into());
        }

        guard.reset_master_password(&new_password)?;
        println!("Master password reset.");

        Ok(())
    }

    fn handle_purge() -> Result<(), Box<dyn std::error::Error>> {
        if !Cortex::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;
        let guard = Cortex::new(&master_password)?;

        if !guard.verify_master_password()? {
            return Err("Authentication failed".into());
        }

        println!();
        println!("WARNING: This will permanently delete all stored passwords!");
        println!();

        let (puzzle, answer) = Utils::generate_math_puzzle();
        println!("Solve this equation to confirm: {}", puzzle);

        let user_answer = UserPrompt::text("Answer: ")?;
        let user_num: i64 = user_answer.as_str().parse().map_err(|_| "Invalid number")?;

        if user_num != answer {
            println!("Wrong answer. Destruction cancelled.");
            return Ok(());
        }

        guard.purge_database()?;
        println!("Database purged.");

        Ok(())
    }

    fn handle_pass(
        length: usize,
        count: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        special: bool,
        no_ambiguous: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if length < 4 {
            eprintln!("Error: Password length must be at least 4 characters.");
            process::exit(1);
        }

        if length > 128 {
            eprintln!("Error: Password length too long (max 128 chars).");
            process::exit(1);
        }

        if count < 1 || count > 50 {
            eprintln!("Error: Count must be between 1 and 50.");
            process::exit(1);
        }

        if !uppercase && !lowercase && !digits && !special {
            eprintln!("Error: At least one character type must be enabled.");
            process::exit(1);
        }

        for i in 1..=count {
            match Utils::generate_password(
                length,
                uppercase,
                lowercase,
                digits,
                special,
                no_ambiguous,
            ) {
                Ok(password) => {
                    if count > 1 {
                        println!("{}: {}", i, password);
                    } else {
                        println!("{}", password);
                    }
                }
                Err(e) => {
                    eprintln!("Error generating password: {}", e);
                    process::exit(1);
                }
            }
        }

        Ok(())
    }
}

struct UserPrompt;

impl UserPrompt {
    fn password(prompt: &str) -> Result<SecureString, Box<dyn std::error::Error>> {
        let password = rpassword::prompt_password(prompt)?;

        if password.is_empty() {
            return Err("Empty password not allowed".into());
        }

        if password.len() > 128 {
            return Err("Password too long (max 128 chars)".into());
        }

        Ok(SecureString::new(password))
    }

    fn text(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        print!("{}", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim().to_string();

        if trimmed.len() > 72 {
            return Err("Input too long (max 72 chars)".into());
        }

        Ok(trimmed)
    }
}

struct Utils;

impl Utils {
    fn generate_password(
        length: usize,
        uppercase: bool,
        lowercase: bool,
        digits: bool,
        special: bool,
        no_ambiguous: bool,
    ) -> Result<String, String> {
        let mut charset = String::new();
        let mut required_chars = Vec::new();

        if lowercase {
            let lower = if no_ambiguous {
                "abcdefghijkmnopqrstuvwxyz"
            } else {
                "abcdefghijklmnopqrstuvwxyz"
            };
            charset.push_str(lower);
            required_chars.push(Self::pick_random_char(lower)?);
        }

        if uppercase {
            let upper = if no_ambiguous {
                "ABCDEFGHJKLMNPQRSTUVWXYZ"
            } else {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            };
            charset.push_str(upper);
            required_chars.push(Self::pick_random_char(upper)?);
        }

        if digits {
            let nums = if no_ambiguous {
                "23456789"
            } else {
                "0123456789"
            };
            charset.push_str(nums);
            required_chars.push(Self::pick_random_char(nums)?);
        }

        if special {
            let specs = if no_ambiguous {
                "!@#$%^&*()_+-={}[]|;:,.<>?"
            } else {
                "!@#$%^&*()_+-=[]{}|;:,.<>?"
            };
            charset.push_str(specs);
            required_chars.push(Self::pick_random_char(specs)?);
        }

        if charset.is_empty() {
            return Err("No character types selected".to_string());
        }

        if required_chars.len() > length {
            return Err("Password length too short for required character types".to_string());
        }

        let mut password = String::with_capacity(length);
        let charset_chars: Vec<char> = charset.chars().collect();
        let mut rng = OsRng;

        for &ch in &required_chars {
            password.push(ch);
        }

        for _ in required_chars.len()..length {
            let idx = (rng.next_u32() as usize) % charset_chars.len();
            password.push(charset_chars[idx]);
        }

        let mut password_chars: Vec<char> = password.chars().collect();
        for i in (1..password_chars.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            password_chars.swap(i, j);
        }

        Ok(password_chars.iter().collect())
    }

    fn pick_random_char(charset: &str) -> Result<char, String> {
        let chars: Vec<char> = charset.chars().collect();
        if chars.is_empty() {
            return Err("Empty charset".to_string());
        }

        let mut rng = OsRng;
        let idx = (rng.next_u32() as usize) % chars.len();
        Ok(chars[idx])
    }

    fn validate_password_security(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        let mut missing = Vec::new();

        if !password.chars().any(|c| c.is_lowercase()) {
            missing.push("lowercase letter");
        }

        if !password.chars().any(|c| c.is_uppercase()) {
            missing.push("uppercase letter");
        }

        if !password.chars().any(|c| c.is_ascii_digit()) {
            missing.push("digit");
        }

        if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            missing.push("special character");
        }

        if missing.len() > 1 {
            return Err(format!(
                "Password must contain at least 3 of these 4 types: {}. Missing: {}",
                "lowercase, uppercase, digit, special character",
                missing.join(", ")
            ));
        }

        Ok(())
    }

    fn password_in_desc_found(password: &str, description: &str) -> bool {
        if password.len() < 3 {
            return false;
        }

        let password_lower = password.to_lowercase();
        let description_lower = description.to_lowercase();

        if description_lower.contains(&password_lower) {
            return true;
        }

        let password_chars: Vec<char> = password_lower.chars().collect();
        let description_chars: Vec<char> = description_lower.chars().collect();

        for window_size in (password.len().min(8)..=password.len()).rev() {
            for window in password_chars.windows(window_size) {
                let pattern: String = window.iter().collect();
                if pattern.len() >= 3
                    && description_chars.windows(window_size).any(|desc_window| {
                        let desc_pattern: String = desc_window.iter().collect();
                        desc_pattern == pattern
                    })
                {
                    return true;
                }
            }
        }

        let regex_pattern = format!(r"(?i){}", regex::escape(password));
        if let Ok(re) = Regex::new(&regex_pattern) {
            if re.is_match(description) {
                return true;
            }
        }

        false
    }

    fn generate_math_puzzle() -> (String, i64) {
        let mut rng = OsRng;

        loop {
            let a = (rng.next_u32() % 91 + 10) as i64;
            let b = (rng.next_u32() % 46 + 5) as i64;
            let c = (rng.next_u32() % 38 + 3) as i64;

            let ops = ["+", "-", "*"];
            let op1 = ops[(rng.next_u32() as usize) % ops.len()];
            let op2 = ops[(rng.next_u32() as usize) % ops.len()];

            let intermediate = match op1 {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                _ => unreachable!(),
            };

            if intermediate <= 0 {
                continue;
            }

            let answer = match op2 {
                "+" => intermediate + c,
                "-" => intermediate - c,
                "*" => intermediate * c,
                _ => unreachable!(),
            };

            if answer > 0 {
                return (format!("({} {} {}) {} {}", a, op1, b, op2, c), answer);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => Handler::handle_init(),
        Commands::Create { name } => Handler::handle_create(name),
        Commands::Get { name } => Handler::handle_get(name),
        Commands::List => Handler::handle_list(),
        Commands::Delete { name } => Handler::handle_delete(name),
        Commands::Edit { name } => Handler::handle_edit(name),
        Commands::Find {
            pattern,
            ignore_case,
            names_only,
        } => Handler::handle_find(pattern, ignore_case, names_only),
        Commands::Export => Handler::handle_export(),
        Commands::Reset => Handler::handle_reset(),
        Commands::Purge => Handler::handle_purge(),
        Commands::Pass {
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
            no_ambiguous,
        } => Handler::handle_pass(
            length,
            count,
            uppercase,
            lowercase,
            digits,
            special,
            no_ambiguous,
        ),
    }
}
