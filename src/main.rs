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

use std::io::{self, Write};
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

    #[command(about = "Reset the master password")]
    Reset,

    #[command(about = "Permanently purge the entire password database")]
    Purge,
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
        Commands::Reset => Handler::handle_reset(),
        Commands::Purge => Handler::handle_purge(),
    }
}
