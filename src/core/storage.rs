use crate::core::types::PasswordEntry;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

const INIT_MARKER: &str = "__init__";
const SALT_KEY: &str = "__salt__";
const LOCK_FILE: &str = ".cortex.lock";

pub struct Storage {
    pub(crate) db: sled::Db,
    _lock_file: Option<File>,
}

impl Storage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path();

        let lock_path = db_path
            .parent()
            .ok_or("Invalid database path")?
            .join(LOCK_FILE);

        let lock_file = match File::create(&lock_path) {
            Ok(f) => {
                #[cfg(unix)]
                {
                    use fs2::FileExt;
                    f.try_lock_exclusive()
                        .map_err(|_| "Database is locked by another process")?;
                }
                Some(f)
            }
            Err(e) => return Err(format!("Failed to create lock file: {}", e).into()),
        };

        let db = sled::open(&db_path).map_err(|e| format!("Failed to open database: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = db_path.parent() {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        Ok(Self {
            db,
            _lock_file: lock_file,
        })
    }

    pub fn init_db(
        &self,
        verification_data: &[u8],
        salt: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .insert(INIT_MARKER, verification_data)
            .map_err(|e| format!("Failed to store verification data: {}", e))?;

        self.db
            .insert(SALT_KEY, &salt[..])
            .map_err(|e| format!("Failed to store salt: {}", e))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        self.create_backup()?;

        Ok(())
    }

    pub fn get_salt(&self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        match self.db.get(SALT_KEY)? {
            Some(data) => Ok(Some(data.to_vec())),
            None => Ok(None),
        }
    }

    pub fn get_verification_data(&self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        match self.db.get(INIT_MARKER)? {
            Some(data) => Ok(Some(data.to_vec())),
            None => Ok(None),
        }
    }

    pub fn create_password(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Reserved name prefix".into());
        }

        if self.db.get(name)?.is_some() {
            return Ok(false);
        }

        self.db
            .insert(name, bincode::serialize(entry)?)
            .map_err(|e| format!("Failed to insert password: {}", e))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        Ok(true)
    }

    pub fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        match self.db.get(name)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)
                    .map_err(|e| format!("Failed to deserialize entry: {}", e))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    pub fn list_entries(&self) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())?;

            if !key_str.starts_with("__") {
                let entry: PasswordEntry = bincode::deserialize(&value)
                    .map_err(|e| format!("Failed to deserialize entry '{}': {}", key_str, e))?;
                entries.push((key_str, entry));
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(entries)
    }

    pub fn delete_password(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Cannot delete system entries".into());
        }
        if name.is_empty() {
            return Err("Empty name not allowed".into());
        }

        match self.db.remove(name)? {
            Some(_) => {
                self.db.flush()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn edit_password(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(false);
        }

        if self.db.get(name)?.is_none() {
            return Ok(false);
        }

        self.db
            .insert(name, bincode::serialize(entry)?)
            .map_err(|e| format!("Failed to update password: {}", e))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        Ok(true)
    }

    pub fn search_entries(
        &self,
        pattern: &str,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        if pattern.is_empty() || pattern.trim().is_empty() {
            return Err("Search pattern cannot be empty".into());
        }

        if pattern.len() > 100 {
            return Err("Search pattern too long (max 100 chars)".into());
        }

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

            let entry: PasswordEntry = bincode::deserialize(&value)?;
            results.push((key_str, entry));
        }

        Ok(results)
    }

    pub fn get_all_entries(
        &self,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())?;

            if !key_str.starts_with("__") {
                let entry: PasswordEntry = bincode::deserialize(&value)?;
                entries.push((key_str, entry));
            }
        }

        Ok(entries)
    }

    pub fn update_entry(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .insert(name, bincode::serialize(entry)?)
            .map_err(|e| format!("Failed to update entry: {}", e))?;

        Ok(())
    }

    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {}", e))?;

        Ok(())
    }

    pub fn purge_database(&self) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn export_entries<W: Write>(
        &self,
        writer: &mut BufWriter<W>,
        process_entry: impl Fn(&str, &PasswordEntry) -> Result<String, Box<dyn std::error::Error>>,
    ) -> Result<(usize, usize), Box<dyn std::error::Error>> {
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
                std::io::stderr().flush()?;
            }

            match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => match process_entry(&key_str, &entry) {
                    Ok(output) => {
                        writeln!(writer, "{}", output)?;
                    }
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
            eprintln!("Warning: {} entries failed to process", failed);
        }

        Ok((processed, failed))
    }

    pub fn create_backup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path();
        let backup_dir = db_path
            .parent()
            .ok_or("Invalid database path")?
            .join("backups");

        fs::create_dir_all(&backup_dir)?;

        let timestamp = crate::core::time::Time::current_timestamp();
        let backup_path = backup_dir.join(format!("backup_{}.db", timestamp));

        self.db.flush()?;

        if let Some(parent) = db_path.parent() {
            for entry in fs::read_dir(parent)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    if !file_name.starts_with('.') {
                        let dest = backup_path
                            .parent()
                            .ok_or("Invalid backup path")?
                            .join(file_name);
                        fs::copy(&path, &dest)?;
                    }
                }
            }
        }

        Self::cleanup_old_backups(&backup_dir, 5)?;

        Ok(())
    }

    fn cleanup_old_backups(
        backup_dir: &PathBuf,
        keep: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut backups: Vec<_> = fs::read_dir(backup_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();

        backups.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));

        if backups.len() > keep {
            for backup in backups.iter().take(backups.len() - keep) {
                fs::remove_file(backup.path())?;
            }
        }

        Ok(())
    }

    pub fn get_db_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("cortex");

        std::fs::create_dir_all(&path).ok();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
        }

        path.push(".password-store");
        path
    }

    pub fn database_exists() -> bool {
        Self::get_db_path().exists()
    }

    pub fn count_entries(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut count = 0;

        for item in self.db.iter() {
            let (key, _) = item?;
            let key_str = String::from_utf8_lossy(&key);

            if !key_str.starts_with("__") {
                count += 1;
            }
        }

        Ok(count)
    }

    pub fn entry_exists(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(self.db.get(name)?.is_some())
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.db.flush();
    }
}
