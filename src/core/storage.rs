use crate::core::types::PasswordEntry;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

const INIT_MARKER: &str = "__init__";
const SALT_KEY: &str = "__salt__";
const LOCK_FILE: &str = ".cortex.lock";

pub struct Storage {
    pub(crate) db: sled::Db,
    _lock_file: Option<File>,
}

impl Storage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;

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
            Err(e) => return Err(format!("Failed to create lock file: {e}").into()),
        };

        let db = sled::open(&db_path).map_err(|e| format!("Failed to open database: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = db_path.parent() {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(
                    |error| format!("Failed to set permissions on {}: {error}", parent.display()),
                )?;
            }
            fs::set_permissions(&db_path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                format!(
                    "Failed to set permissions on {}: {error}",
                    db_path.display()
                )
            })?;
        }

        Ok(Self {
            db,
            _lock_file: lock_file,
        })
    }

    pub fn init_db(
        &self,
        verification_data: &[u8],
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = sled::Batch::default();
        batch.insert(INIT_MARKER, verification_data);
        batch.insert(SALT_KEY, salt);

        self.db
            .apply_batch(batch)
            .map_err(|e| format!("Failed to initialize database: {e}"))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;

        self.create_backup()?;

        Ok(())
    }

    pub fn atomic_reset(
        &self,
        entries: &[(String, PasswordEntry)],
        verification_data: &[u8],
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = sled::Batch::default();

        for (name, entry) in entries {
            let serialized = bincode::serialize(entry)?;
            batch.insert(name.as_bytes(), serialized);
        }

        batch.insert(INIT_MARKER, verification_data);
        batch.insert(SALT_KEY, salt);

        self.db
            .apply_batch(batch)
            .map_err(|e| format!("Failed to apply atomic reset: {e}"))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;

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
            .map_err(|e| format!("Failed to insert password: {e}"))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;

        Ok(true)
    }

    pub fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(None);
        }

        match self.db.get(name)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)
                    .map_err(|e| format!("Failed to deserialize entry: {e}"))?;
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
                    .map_err(|e| format!("Failed to deserialize entry '{key_str}': {e}"))?;
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
            .map_err(|e| format!("Failed to update password: {e}"))?;

        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;

        Ok(true)
    }

    pub fn search_entries(
        &self,
        pattern: &str,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        if pattern.trim().is_empty() {
            return Err("Search pattern cannot be empty".into());
        }

        if pattern.len() > 100 {
            return Err("Search pattern too long (max 100 chars)".into());
        }

        let mut results = Vec::new();
        let mut processed = 0;

        for item in self.db.iter() {
            let (key, value) = item?;
            let key_str = match String::from_utf8(key.to_vec()) {
                Ok(name) => name,
                Err(error) => {
                    eprintln!("Warning: skipping entry with an invalid name: {error}");
                    continue;
                }
            };

            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;
            if processed > 50_000 {
                return Err("Too many entries to search".into());
            }

            let entry = match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!("Warning: skipping invalid entry '{key_str}': {error}");
                    continue;
                }
            };
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
            .map_err(|e| format!("Failed to update entry: {e}"))?;

        Ok(())
    }

    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush database: {e}"))?;

        Ok(())
    }

    pub fn purge_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.db.clear()?;
        self.db.flush()?;

        let db_path = Self::get_db_path()?;
        if db_path.exists() {
            if let Some(parent) = db_path.parent() {
                let backup_dir = parent.join("backups");
                if backup_dir.exists() {
                    let _ = fs::remove_dir_all(&backup_dir);
                }
            }
            let _ = fs::remove_dir_all(&db_path);
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
            let Ok((key, value)) = item else { continue };

            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("__") {
                continue;
            }

            processed += 1;

            if processed % 1000 == 0 {
                writer.flush()?;
                eprint!("\rProcessed {processed} entries...");
                std::io::stderr().flush()?;
            }

            match bincode::deserialize::<PasswordEntry>(&value) {
                Ok(entry) => match process_entry(&key_str, &entry) {
                    Ok(output) => {
                        writeln!(writer, "{output}")?;
                    }
                    Err(_) => failed += 1,
                },
                Err(_) => failed += 1,
            }
        }

        writer.flush()?;

        if processed >= 1000 {
            eprintln!("\rCompleted {processed} entries.");
        }

        if failed > 0 {
            eprintln!("Warning: {failed} entries failed to process");
        }

        Ok((processed, failed))
    }

    pub fn create_backup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        let backup_dir = db_path
            .parent()
            .ok_or("Invalid database path")?
            .join("backups");

        fs::create_dir_all(&backup_dir).map_err(|error| {
            format!(
                "Failed to create directory {}: {error}",
                backup_dir.display()
            )
        })?;
        Self::restrict_directory(&backup_dir)?;

        let timestamp = crate::core::time::Time::current_timestamp();
        let backup_path = backup_dir.join(format!("backup_{timestamp}"));

        self.db.flush()?;
        let snapshot = self.db.export();
        let backup_db = sled::open(&backup_path)
            .map_err(|error| format!("Failed to create backup database: {error}"))?;
        backup_db.import(snapshot);
        backup_db
            .flush()
            .map_err(|error| format!("Failed to flush backup database: {error}"))?;
        drop(backup_db);

        Self::cleanup_old_backups(&backup_dir, 5)?;

        Ok(())
    }

    fn cleanup_old_backups(
        backup_dir: &Path,
        keep: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut backups: Vec<_> = fs::read_dir(backup_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|s| s.starts_with("backup_"))
            })
            .collect();

        backups.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));

        if backups.len() > keep {
            for backup in backups.iter().take(backups.len() - keep) {
                let path = backup.path();
                if path.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
                }
            }
        }

        Ok(())
    }

    pub fn get_db_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut path =
            dirs::config_dir().ok_or("Could not determine the configuration directory")?;
        path.push("cortex");
        fs::create_dir_all(&path)
            .map_err(|error| format!("Failed to create directory {}: {error}", path.display()))?;
        Self::restrict_directory(&path)?;
        path.push(".password-store");
        Ok(path)
    }

    fn restrict_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                format!("Failed to set permissions on {}: {error}", path.display())
            })?;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
    }

    pub fn database_exists() -> Result<bool, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        Ok(db_path.exists() && db_path.join("conf").exists())
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
        if name.starts_with("__") {
            return Ok(false);
        }
        Ok(self.db.get(name)?.is_some())
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.db.flush();
    }
}
