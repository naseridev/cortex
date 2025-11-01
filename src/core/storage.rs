use crate::core::types::PasswordEntry;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

const INIT_MARKER: &str = "__init__";

pub struct Storage {
    pub(crate) db: sled::Db,
}

impl Storage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path();
        let db = sled::open(&db_path)?;

        #[cfg(unix)]
        {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = db_path.parent() {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        Ok(Self { db })
    }

    pub fn init_db(&self, test_entry: &PasswordEntry) -> Result<(), Box<dyn std::error::Error>> {
        self.db
            .insert(INIT_MARKER, bincode::serialize(test_entry)?)?;
        self.db.flush()?;

        Ok(())
    }

    pub fn get_init_marker(&self) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        match self.db.get(INIT_MARKER)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)?;
                Ok(Some(entry))
            }
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

        self.db.insert(name, bincode::serialize(entry)?)?;
        self.db.flush()?;

        Ok(true)
    }

    pub fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        match self.db.get(name)? {
            Some(data) => {
                let entry: PasswordEntry = bincode::deserialize(&data)?;
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
                let entry: PasswordEntry = bincode::deserialize(&value)?;
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

        self.db.insert(name, bincode::serialize(entry)?)?;
        self.db.flush()?;

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
        self.db.insert(name, bincode::serialize(entry)?)?;

        Ok(())
    }

    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.db.flush()?;

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

    pub fn get_db_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("cortex");

        std::fs::create_dir_all(&path).ok();

        #[cfg(unix)]
        {
            use std::fs;
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
