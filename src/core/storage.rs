use crate::core::{
    crypto::Crypto,
    dump::{self, DumpFile},
    limits::MAX_ENTRIES,
    platform,
    types::PasswordEntry,
};
use redb::{Database, DatabaseError, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const VAULT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault");
const DB_FILE: &str = "vault.redb";
const LEGACY_DB_DIR: &str = ".password-store";
const LOCK_FILE: &str = ".cortex.lock";
const DUMP_DIR: &str = "dumps";
const LEGACY_BACKUP_DIR: &str = "backups";
const INIT_MARKER: &str = "__init__";
const SALT_KEY: &str = "__salt__";
const FAILED_ATTEMPTS_KEY: &str = "__throttle__";
const MANIFEST_KEY: &str = "__manifest__";
const DUMP_PREFIX: &str = "dump_";
const DUMP_SUFFIX: &str = ".bin";
const INVALID_DUMP_MESSAGE: &str = "Dump content is invalid or damaged.";
const WRONG_PASSWORD_OR_DAMAGED_MESSAGE: &str = "Wrong master password or damaged dump file.";
const DUMP_HEADER_MISMATCH_MESSAGE: &str = "Dump header does not match its contents.";
const DUMP_INTEGRITY_MESSAGE: &str = "Dump integrity check failed.";
const INTEGRITY_FAILED_MESSAGE: &str = "Database integrity check failed. Stored data was modified, replaced or removed outside of cortex.";
const LEGACY_VAULT_MESSAGE: &str =
    "This vault predates integrity protection. Run 'reset' once to upgrade it.";
const LEGACY_DATABASE_MESSAGE: &str = "A database from an older cortex version was found. Export it to CSV with that version, run 'init' here, then 'import' the CSV.";
const DATABASE_LOCKED_MESSAGE: &str = "Database is locked by another process";

type Changes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
type Records = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) fn encode_value<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(value).map_err(|error| format!("Failed to serialize data: {error}"))
}

pub(crate) fn decode_value<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, String> {
    postcard::from_bytes(bytes).map_err(|error| format!("Failed to deserialize data: {error}"))
}

pub struct Snapshot {
    entries: Records,
    user_count: usize,
}

impl Snapshot {
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.user_count
    }
}

pub struct Storage {
    db: Database,
    integrity: Cell<Option<[u8; 32]>>,
}

impl Storage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        Self::open_at(&db_path)
    }

    pub fn open_at(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !db_path.exists() {
            platform::create_private_file(db_path)
                .map(drop)
                .map_err(|error| format!("Failed to create database file: {error}"))?;
        }

        let db = Database::create(db_path).map_err(|error| match error {
            DatabaseError::DatabaseAlreadyOpen => DATABASE_LOCKED_MESSAGE.to_string(),
            other => format!("Failed to open database: {other}"),
        })?;

        platform::restrict_to_owner(db_path).map_err(|error| {
            format!(
                "Failed to set permissions on {}: {error}",
                db_path.display()
            )
        })?;

        let txn = db.begin_write()?;
        txn.open_table(VAULT)?;
        txn.commit()?;
        Ok(Self {
            db,
            integrity: Cell::new(None),
        })
    }

    pub fn bind_integrity(&self, crypto: &Crypto) {
        self.set_integrity(Some(crypto.integrity_key()));
    }

    pub fn init_db(&self, crypto: &Crypto, salt: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.bind_integrity(crypto);
        let meta = [
            (INIT_MARKER, crypto.verification()),
            (SALT_KEY, salt.to_vec()),
        ];
        self.commit(&Changes::new(), &meta)
    }

    pub fn atomic_reset(
        &self,
        entries: &[(String, PasswordEntry)],
        crypto: &Crypto,
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut changes = Changes::new();
        for (key, _) in self.records()? {
            if !key.starts_with(b"__") {
                changes.insert(key, None);
            }
        }
        for (name, entry) in entries {
            changes.insert(name.as_bytes().to_vec(), Some(encode_value(entry)?));
        }

        self.set_integrity(Some(crypto.integrity_key()));
        let meta = [
            (INIT_MARKER, crypto.verification()),
            (SALT_KEY, salt.to_vec()),
        ];
        self.commit(&changes, &meta)
    }

    pub fn verify_integrity(&self) -> Result<(), Box<dyn std::error::Error>> {
        let key = self.integrity_key()?;
        let records = self.records()?;
        let expected = digest_records(&key, &records, &Changes::new());
        match self.get_raw(MANIFEST_KEY.as_bytes())? {
            Some(stored) => {
                let stored_bytes =
                    <[u8; 32]>::try_from(&stored[..]).map_err(|_| INTEGRITY_FAILED_MESSAGE)?;
                if blake3::Hash::from(stored_bytes) == expected {
                    Ok(())
                } else {
                    Err(INTEGRITY_FAILED_MESSAGE.into())
                }
            }
            None => {
                if records.iter().any(|(name, _)| !name.starts_with(b"__")) {
                    Err(LEGACY_VAULT_MESSAGE.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn get_salt(&self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        self.get_raw(SALT_KEY.as_bytes())
    }

    pub fn get_verification_data(&self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        self.get_raw(INIT_MARKER.as_bytes())
    }

    pub(crate) fn failed_attempts(&self) -> Result<u32, Box<dyn std::error::Error>> {
        Ok(match self.get_raw(FAILED_ATTEMPTS_KEY.as_bytes())? {
            Some(data) => <[u8; 4]>::try_from(data.as_slice()).map_or(0, u32::from_le_bytes),
            None => 0,
        })
    }

    pub(crate) fn record_failed_attempt(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let next = self.failed_attempts()?.saturating_add(1);
        self.put_raw(FAILED_ATTEMPTS_KEY.as_bytes(), &next.to_le_bytes())?;
        Ok(next)
    }

    pub(crate) fn clear_failed_attempts(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.remove_raw(FAILED_ATTEMPTS_KEY.as_bytes())
    }

    pub fn create_password(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        Self::check_writable_name(name)?;

        if self.get_raw(name.as_bytes())?.is_some() {
            return Ok(false);
        }

        let mut changes = Changes::new();
        changes.insert(name.as_bytes().to_vec(), Some(encode_value(entry)?));
        self.commit(&changes, &[])?;
        Ok(true)
    }

    pub fn put_entries(
        &self,
        entries: &[(String, PasswordEntry)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut changes = Changes::new();
        for (name, entry) in entries {
            Self::check_writable_name(name)?;
            changes.insert(name.as_bytes().to_vec(), Some(encode_value(entry)?));
        }
        if changes.is_empty() {
            return Ok(());
        }
        self.commit(&changes, &[])
    }

    pub fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(None);
        }

        match self.get_raw(name.as_bytes())? {
            Some(data) => Ok(Some(decode_value(&data)?)),
            None => Ok(None),
        }
    }

    pub fn list_entries(&self) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = self.get_all_entries()?;
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

        if self.get_raw(name.as_bytes())?.is_none() {
            return Ok(false);
        }

        let mut changes = Changes::new();
        changes.insert(name.as_bytes().to_vec(), None);
        self.commit(&changes, &[])?;
        Ok(true)
    }

    pub fn edit_password(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(false);
        }

        if self.get_raw(name.as_bytes())?.is_none() {
            return Ok(false);
        }

        let mut changes = Changes::new();
        changes.insert(name.as_bytes().to_vec(), Some(encode_value(entry)?));
        self.commit(&changes, &[])?;
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

        for (key, value) in self.records()? {
            let key_str = match String::from_utf8(key) {
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
            if processed > MAX_ENTRIES {
                return Err("Too many entries to search".into());
            }

            match decode_value::<PasswordEntry>(&value) {
                Ok(entry) => results.push((key_str, entry)),
                Err(error) => eprintln!("Warning: skipping invalid entry '{key_str}': {error}"),
            }
        }

        Ok(results)
    }

    pub fn get_all_entries(
        &self,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();

        for (key, value) in self.records()? {
            let key_str = String::from_utf8(key)?;
            if !key_str.starts_with("__") {
                let entry: PasswordEntry = decode_value(&value)?;
                entries.push((key_str, entry));
            }
        }

        Ok(entries)
    }

    pub fn purge_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        let txn = self.db.begin_write()?;
        txn.delete_table(VAULT)?;
        txn.commit()?;

        let db_path = Self::get_db_path()?;
        if let Some(parent) = db_path.parent() {
            for directory in [DUMP_DIR, LEGACY_BACKUP_DIR, LEGACY_DB_DIR] {
                let _ = fs::remove_dir_all(parent.join(directory));
            }
            let _ = fs::remove_file(parent.join(LOCK_FILE));
        }
        let _ = fs::remove_file(&db_path);

        Ok(())
    }

    pub fn create_dump(&self, crypto: &Crypto) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dump_dir = std::env::current_dir()
            .map_err(|error| format!("Failed to read the current directory: {error}"))?;
        self.write_dump(&dump_dir, crypto)
    }

    pub fn read_dump(
        file: &DumpFile,
        crypto: &Crypto,
    ) -> Result<Snapshot, Box<dyn std::error::Error>> {
        let mut plain = crypto
            .open_dump(&file.nonce, &file.ciphertext)
            .map_err(|_| WRONG_PASSWORD_OR_DAMAGED_MESSAGE)?;
        let parsed: Result<Records, String> = decode_value(&plain);
        plain.zeroize();
        let entries = parsed.map_err(|_| INVALID_DUMP_MESSAGE)?;

        let find = |key: &str| -> Option<&[u8]> {
            entries
                .iter()
                .find(|(name, _)| name.as_slice() == key.as_bytes())
                .map(|(_, value)| value.as_slice())
        };
        let init = find(INIT_MARKER).ok_or(INVALID_DUMP_MESSAGE)?;
        let salt = find(SALT_KEY).ok_or(INVALID_DUMP_MESSAGE)?;
        let manifest = find(MANIFEST_KEY).ok_or(INVALID_DUMP_MESSAGE)?;

        if salt != file.salt.as_slice() {
            return Err(DUMP_HEADER_MISMATCH_MESSAGE.into());
        }
        if !crypto.matches_verification(init) {
            return Err(WRONG_PASSWORD_OR_DAMAGED_MESSAGE.into());
        }
        let stored_manifest = <[u8; 32]>::try_from(manifest).map_err(|_| INVALID_DUMP_MESSAGE)?;
        let expected = snapshot_digest(&crypto.integrity_key(), &entries);
        if blake3::Hash::from(stored_manifest) != expected {
            return Err(DUMP_INTEGRITY_MESSAGE.into());
        }

        let user_count = entries
            .iter()
            .filter(|(name, _)| !name.starts_with(b"__"))
            .count();
        Ok(Snapshot {
            entries,
            user_count,
        })
    }

    pub fn replace_with_dump(&self, snapshot: &Snapshot) -> Result<(), Box<dyn std::error::Error>> {
        let txn = self.db.begin_write()?;
        {
            txn.delete_table(VAULT)?;
            let mut table = txn.open_table(VAULT)?;
            for (name, value) in &snapshot.entries {
                if name.as_slice() != FAILED_ATTEMPTS_KEY.as_bytes() {
                    table.insert(name.as_slice(), value.as_slice())?;
                }
            }
        }
        txn.commit()
            .map_err(|error| format!("Failed to restore database: {error}"))?;
        Ok(())
    }

    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VAULT)?;
        Ok(table.get(key)?.map(|guard| guard.value().to_vec()))
    }

    pub fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(VAULT)?;
            table.insert(key, value)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn remove_raw(&self, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(VAULT)?;
            table.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn records(&self) -> Result<Records, Box<dyn std::error::Error>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VAULT)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (key, value) = item?;
            records.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(records)
    }

    pub fn write_dump(
        &self,
        dump_dir: &Path,
        crypto: &Crypto,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        fs::create_dir_all(dump_dir).map_err(|error| {
            format!("Failed to create directory {}: {error}", dump_dir.display())
        })?;

        let salt = self
            .get_salt()?
            .ok_or("Database salt not found. Database may be corrupted.")?;
        let snapshot = self.records()?;
        let mut plain = encode_value(&snapshot)?;
        drop(snapshot);
        let sealed = crypto.seal_dump(&plain);
        plain.zeroize();
        let (ciphertext, nonce) = sealed?;

        let bytes = dump::encode(&DumpFile {
            salt,
            nonce,
            ciphertext,
        })?;
        let path = dump_dir.join(format!(
            "{DUMP_PREFIX}{:020}{DUMP_SUFFIX}",
            Self::dump_stamp()
        ));
        Self::write_new_file(&path, &bytes)?;

        Ok(path)
    }

    fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let directory = path.parent().unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            format!("Failed to create dump in {}: {error}", directory.display())
        })?;
        temp.write_all(bytes)
            .map_err(|error| format!("Failed to write dump {}: {error}", path.display()))?;
        temp.as_file()
            .sync_all()
            .map_err(|error| format!("Failed to write dump {}: {error}", path.display()))?;
        platform::restrict_to_owner(temp.path())
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;
        temp.persist_noclobber(path)
            .map_err(|error| format!("Failed to save dump {}: {}", path.display(), error.error))?;
        Ok(())
    }

    fn dump_stamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    }

    pub fn get_db_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut path =
            platform::config_dir().ok_or("Could not determine the configuration directory")?;
        path.push("cortex");
        fs::create_dir_all(&path)
            .map_err(|error| format!("Failed to create directory {}: {error}", path.display()))?;
        platform::restrict_to_owner(&path)
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;
        path.push(DB_FILE);
        Ok(path)
    }

    pub fn database_exists() -> Result<bool, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        Ok(fs::metadata(&db_path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
    }

    pub fn legacy_database_present() -> Result<bool, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        Ok(db_path
            .parent()
            .is_some_and(|parent| parent.join(LEGACY_DB_DIR).exists()))
    }

    #[must_use]
    pub fn legacy_database_message() -> &'static str {
        LEGACY_DATABASE_MESSAGE
    }

    pub fn entry_exists(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Ok(false);
        }
        Ok(self.get_raw(name.as_bytes())?.is_some())
    }

    fn check_writable_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if name.is_empty() {
            return Err("Empty name not allowed".into());
        }
        if name.starts_with("__") {
            return Err("Reserved name prefix".into());
        }
        Ok(())
    }

    fn set_integrity(&self, key: Option<[u8; 32]>) {
        if let Some(mut previous) = self.integrity.replace(key) {
            previous.zeroize();
        }
    }

    fn integrity_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.integrity
            .get()
            .ok_or_else(|| "Storage is not bound to a vault key".into())
    }

    fn commit(
        &self,
        changes: &Changes,
        meta: &[(&str, Vec<u8>)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = self.integrity_key()?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(VAULT)?;
            let mut existing = Vec::new();
            for item in table.iter()? {
                let (db_key, db_value) = item?;
                existing.push((db_key.value().to_vec(), db_value.value().to_vec()));
            }
            let manifest = digest_records(&key, &existing, changes);

            for (name, value) in changes {
                match value {
                    Some(bytes) => {
                        table.insert(name.as_slice(), bytes.as_slice())?;
                    }
                    None => {
                        table.remove(name.as_slice())?;
                    }
                }
            }
            for (name, value) in meta {
                table.insert(name.as_bytes(), value.as_slice())?;
            }
            table.insert(MANIFEST_KEY.as_bytes(), manifest.as_bytes().as_slice())?;
        }
        txn.commit()
            .map_err(|error| format!("Failed to write database: {error}"))?;
        Ok(())
    }
}

fn digest_records(
    key: &[u8; 32],
    records: &[(Vec<u8>, Vec<u8>)],
    changes: &Changes,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    let mut pending = changes.iter().peekable();

    for (db_key, db_value) in records {
        if db_key.starts_with(b"__") {
            continue;
        }

        while let Some((change_key, change_value)) =
            pending.next_if(|(name, _)| name.as_slice() < db_key.as_slice())
        {
            feed_change(&mut hasher, change_key, change_value.as_deref());
        }

        match pending.next_if(|(name, _)| name.as_slice() == db_key.as_slice()) {
            Some((change_key, change_value)) => {
                feed_change(&mut hasher, change_key, change_value.as_deref());
            }
            None => feed_record(&mut hasher, db_key, db_value),
        }
    }

    for (change_key, change_value) in pending {
        feed_change(&mut hasher, change_key, change_value.as_deref());
    }

    hasher.finalize()
}

fn feed_record(hasher: &mut blake3::Hasher, name: &[u8], value: &[u8]) {
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(name);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn feed_change(hasher: &mut blake3::Hasher, name: &[u8], value: Option<&[u8]>) {
    if let Some(value) = value {
        feed_record(hasher, name, value);
    }
}

fn snapshot_digest(key: &[u8; 32], entries: &[(Vec<u8>, Vec<u8>)]) -> blake3::Hash {
    let mut records: Vec<&(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .filter(|(name, _)| !name.starts_with(b"__"))
        .collect();
    records.sort_by(|left, right| left.0.cmp(&right.0));

    let mut hasher = blake3::Hasher::new_keyed(key);
    for (name, value) in records {
        feed_record(&mut hasher, name, value);
    }
    hasher.finalize()
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.set_integrity(None);
    }
}
