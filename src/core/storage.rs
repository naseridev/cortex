pub use crate::core::snapshot::Snapshot;

use crate::{
    core::{
        accounts::Accounts,
        crypto::Crypto,
        integrity::{Changes, Integrity, MANIFEST_KEY, Records},
        limits::MAX_ENTRIES,
        platform::Platform,
        time::Time,
        types::PasswordEntry,
    },
    formats::dump::DumpFile,
};
use redb::{Database, DatabaseError, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const RESERVED_PREFIX: &str = "__";

pub(crate) const INIT_MARKER: &str = "__init__";
pub(crate) const SALT_KEY: &str = "__salt__";
pub(crate) const FAILED_ATTEMPTS_KEY: &str = "__throttle__";
pub(crate) const TOMBSTONE_PREFIX: &str = "__tombstone__/";
pub(crate) const CLOCK_KEY: &str = "__clock__";

const VAULT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault");
const LEGACY_DB_DIR: &str = ".password-store";
const MAX_SEARCH_PATTERN_BYTES: usize = 100;
const LEGACY_DATABASE_MESSAGE: &str = "A database from an older cortex version was found. Export it to CSV with that version, run 'account create' here, then 'import' the CSV.";
const DATABASE_LOCKED_MESSAGE: &str = "Database is locked by another process";

pub struct Storage {
    db: Database,
    integrity: Cell<Option<[u8; 32]>>,
}

impl Storage {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Self::get_db_path()?;
        Self::open_at(&db_path)
    }

    pub fn open_account(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = Accounts::db_path(name)?;
        Self::open_at(&db_path)
    }

    pub fn open_at(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !db_path.exists() {
            Platform::create_private_file(db_path)
                .map(drop)
                .map_err(|error| format!("Failed to create database file: {error}"))?;
        }

        let db = Database::create(db_path).map_err(|error| match error {
            DatabaseError::DatabaseAlreadyOpen => DATABASE_LOCKED_MESSAGE.to_string(),
            other => format!("Failed to open database: {other}"),
        })?;

        Platform::restrict_to_owner(db_path).map_err(|error| {
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
        self.commit(
            &Changes::new(),
            &Self::initialization_metadata(crypto, salt),
        )
    }

    pub fn atomic_reset(
        &self,
        entries: &[(String, PasswordEntry)],
        crypto: &Crypto,
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.rewrite_vault(entries, None, None, crypto, salt)
    }

    pub fn atomic_merge(
        &self,
        entries: &[(String, PasswordEntry)],
        tombstones: &[(String, u64)],
        clock: u64,
        crypto: &Crypto,
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let merged_clock = self.clock()?.max(clock);
        self.rewrite_vault(entries, Some(tombstones), Some(merged_clock), crypto, salt)
    }

    fn rewrite_vault(
        &self,
        entries: &[(String, PasswordEntry)],
        tombstones: Option<&[(String, u64)]>,
        clock: Option<u64>,
        crypto: &Crypto,
        salt: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut changes = Changes::new();
        for (key, _) in self.records()? {
            let replaced = if Integrity::is_tombstone_key(&key) {
                tombstones.is_some()
            } else {
                !Integrity::is_reserved_key(&key)
            };
            if replaced {
                changes.insert(key, None);
            }
        }

        for (name, entry) in entries {
            changes.insert(name.as_bytes().to_vec(), Some(Self::encode_value(entry)?));
        }

        for (name, deleted_at) in tombstones.unwrap_or(&[]) {
            changes.insert(
                Self::tombstone_key(name),
                Some(Self::encode_value(deleted_at)?),
            );
        }

        if let Some(value) = clock {
            changes.insert(
                CLOCK_KEY.as_bytes().to_vec(),
                Some(Self::encode_value(&value)?),
            );
        }

        self.set_integrity(Some(crypto.integrity_key()));
        self.commit(&changes, &Self::initialization_metadata(crypto, salt))
    }

    pub fn verify_integrity(&self) -> Result<(), Box<dyn std::error::Error>> {
        let key = self.integrity_key()?;
        let records = self.records()?;
        let stored_manifest = self.get_raw(MANIFEST_KEY.as_bytes())?;
        Integrity::verify_manifest(&key, &records, stored_manifest)
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

    pub fn clock(&self) -> Result<u64, Box<dyn std::error::Error>> {
        match self.get_raw(CLOCK_KEY.as_bytes())? {
            Some(data) => {
                let stored: u64 = Self::decode_value(&data)?;
                Ok(stored)
            }
            None => Self::clock_from_records(&self.records()?),
        }
    }

    pub(crate) fn clock_from_records(
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let mut latest = 0u64;
        for (key, value) in records {
            if key.as_slice() == CLOCK_KEY.as_bytes() || Integrity::is_tombstone_key(key) {
                let stamp: u64 = Self::decode_value(value)?;
                latest = latest.max(stamp);
            } else if !Integrity::is_reserved_key(key) {
                let entry: PasswordEntry = Self::decode_value(value)?;
                latest = latest.max(entry.timestamp);
            }
        }
        Ok(latest)
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

        let stamp = Self::hybrid_stamp(self.clock()?, entry.timestamp);
        let stamped = Self::with_timestamp(entry, stamp);
        self.commit(&Self::entry_changes(name, &stamped, stamp)?, &[])?;
        Ok(true)
    }

    pub fn put_entries(
        &self,
        entries: &[(String, PasswordEntry)],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut clock = self.clock()?;
        let mut changes = Changes::new();
        for (name, entry) in entries {
            Self::check_writable_name(name)?;
            clock = Self::hybrid_stamp(clock, entry.timestamp);
            let stamped = Self::with_timestamp(entry, clock);
            changes.extend(Self::live_changes(name, Self::encode_value(&stamped)?));
        }

        if changes.is_empty() {
            return Ok(());
        }

        changes.insert(
            CLOCK_KEY.as_bytes().to_vec(),
            Some(Self::encode_value(&clock)?),
        );
        self.commit(&changes, &[])
    }

    pub fn get_password(
        &self,
        name: &str,
    ) -> Result<Option<PasswordEntry>, Box<dyn std::error::Error>> {
        if Integrity::is_reserved_name(name) {
            return Ok(None);
        }

        match self.get_raw(name.as_bytes())? {
            Some(data) => Ok(Some(Self::decode_value(&data)?)),
            None => Ok(None),
        }
    }

    pub fn list_entries(&self) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = self.get_all_entries()?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    pub fn list_tombstones(&self) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
        let mut tombstones = Vec::new();
        for (key, value) in self.records()? {
            if let Some(name) = Self::tombstone_name(&key) {
                let deleted_at: u64 = Self::decode_value(&value)?;
                tombstones.push((name, deleted_at));
            }
        }
        tombstones.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(tombstones)
    }

    pub fn delete_password(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if Integrity::is_reserved_name(name) {
            return Err("Cannot delete system entries".into());
        }

        if name.is_empty() {
            return Err("Empty name not allowed".into());
        }

        if self.get_raw(name.as_bytes())?.is_none() {
            return Ok(false);
        }

        let stamp = Self::hybrid_stamp(self.clock()?, Time::current_timestamp());
        let mut changes = Changes::new();
        changes.insert(name.as_bytes().to_vec(), None);
        changes.insert(Self::tombstone_key(name), Some(Self::encode_value(&stamp)?));
        changes.insert(
            CLOCK_KEY.as_bytes().to_vec(),
            Some(Self::encode_value(&stamp)?),
        );
        self.commit(&changes, &[])?;
        Ok(true)
    }

    pub fn edit_password(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if Integrity::is_reserved_name(name) {
            return Ok(false);
        }

        if self.get_raw(name.as_bytes())?.is_none() {
            return Ok(false);
        }

        let stamp = Self::hybrid_stamp(self.clock()?, entry.timestamp);
        let stamped = Self::with_timestamp(entry, stamp);
        self.commit(&Self::entry_changes(name, &stamped, stamp)?, &[])?;
        Ok(true)
    }

    pub fn search_entries(
        &self,
        pattern: &str,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        if pattern.trim().is_empty() {
            return Err("Search pattern cannot be empty".into());
        }

        if pattern.len() > MAX_SEARCH_PATTERN_BYTES {
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

            if Integrity::is_reserved_name(&key_str) {
                continue;
            }

            processed += 1;
            if processed > MAX_ENTRIES {
                return Err("Too many entries to search".into());
            }

            match Self::decode_value::<PasswordEntry>(&value) {
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

            if !Integrity::is_reserved_name(&key_str) {
                let entry: PasswordEntry = Self::decode_value(&value)?;
                entries.push((key_str, entry));
            }
        }

        Ok(entries)
    }

    pub fn encode_dump(&self, crypto: &Crypto) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Snapshot::encode_bytes(self, crypto)
    }

    pub fn create_dump(&self, crypto: &Crypto) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let dump_dir = std::env::current_dir()
            .map_err(|error| format!("Failed to read the current directory: {error}"))?;
        self.write_dump(&dump_dir, crypto)
    }

    pub fn write_dump(
        &self,
        dump_dir: &Path,
        crypto: &Crypto,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Snapshot::write_to_dir(self, dump_dir, crypto)
    }

    pub fn read_dump(
        file: &DumpFile,
        crypto: &Crypto,
    ) -> Result<Snapshot, Box<dyn std::error::Error>> {
        Snapshot::from_dump(file, crypto)
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

    #[must_use]
    pub fn account_file_name(name: &str) -> String {
        Accounts::file_name(name)
    }

    pub fn get_db_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let active = Accounts::active()?.ok_or(crate::core::accounts::NO_ACCOUNTS)?;
        Accounts::db_path(&active)
    }

    pub fn database_exists() -> Result<bool, Box<dyn std::error::Error>> {
        let Some(active) = Accounts::active()? else {
            return Ok(false);
        };

        Accounts::db_file_exists(&active)
    }

    pub fn legacy_database_present() -> Result<bool, Box<dyn std::error::Error>> {
        let dir = Accounts::cortex_dir()?;
        Ok(dir.join(LEGACY_DB_DIR).exists())
    }

    #[must_use]
    pub fn legacy_database_message() -> &'static str {
        LEGACY_DATABASE_MESSAGE
    }

    pub fn entry_exists(&self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if Integrity::is_reserved_name(name) {
            return Ok(false);
        }

        Ok(self.get_raw(name.as_bytes())?.is_some())
    }

    fn check_writable_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if name.is_empty() {
            return Err("Empty name not allowed".into());
        }

        if Integrity::is_reserved_name(name) {
            return Err("Reserved name prefix".into());
        }

        Ok(())
    }

    fn hybrid_stamp(clock: u64, wall: u64) -> u64 {
        wall.max(clock.saturating_add(1))
    }

    fn with_timestamp(entry: &PasswordEntry, timestamp: u64) -> PasswordEntry {
        let mut stamped = entry.clone();
        stamped.timestamp = timestamp;
        stamped
    }

    fn tombstone_key(name: &str) -> Vec<u8> {
        format!("{TOMBSTONE_PREFIX}{name}").into_bytes()
    }

    pub(crate) fn tombstone_name(key: &[u8]) -> Option<String> {
        let suffix = key.strip_prefix(TOMBSTONE_PREFIX.as_bytes())?;
        String::from_utf8(suffix.to_vec()).ok()
    }

    fn live_changes(name: &str, value: Vec<u8>) -> Changes {
        let mut changes = Changes::new();
        changes.insert(name.as_bytes().to_vec(), Some(value));
        changes.insert(Self::tombstone_key(name), None);
        changes
    }

    fn entry_changes(
        name: &str,
        entry: &PasswordEntry,
        clock: u64,
    ) -> Result<Changes, Box<dyn std::error::Error>> {
        let mut changes = Self::live_changes(name, Self::encode_value(entry)?);
        changes.insert(
            CLOCK_KEY.as_bytes().to_vec(),
            Some(Self::encode_value(&clock)?),
        );
        Ok(changes)
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

    fn initialization_metadata(crypto: &Crypto, salt: &[u8]) -> [(&'static str, Vec<u8>); 2] {
        [
            (INIT_MARKER, crypto.verification()),
            (SALT_KEY, salt.to_vec()),
        ]
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

            let manifest = Integrity::digest_records(&key, &existing, changes);

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

    pub(crate) fn encode_value<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
        postcard::to_allocvec(value).map_err(|error| format!("Failed to serialize data: {error}"))
    }

    pub(crate) fn decode_value<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, String> {
        postcard::from_bytes(bytes).map_err(|error| format!("Failed to deserialize data: {error}"))
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        self.set_integrity(None);
    }
}
