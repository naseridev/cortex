use crate::{
    security::crypto::Crypto,
    storage::{
        accounts::{Accounts, NO_ACCOUNTS},
        integrity::{Changes, Integrity, MANIFEST_KEY, Records},
    },
    system::platform::Platform,
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

pub(crate) const VAULT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vault");
const LEGACY_DB_DIR: &str = ".password-store";
const LEGACY_DATABASE_MESSAGE: &str = "A database from an older cortex version was found. Export it to CSV with that version, run 'account create' here, then 'import' the CSV.";
const DATABASE_LOCKED_MESSAGE: &str = "Database is locked by another process";

pub struct Storage {
    pub(crate) db: Database,
    pub(crate) integrity: Cell<Option<[u8; 32]>>,
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

    pub fn verify_integrity(&self) -> Result<(), Box<dyn std::error::Error>> {
        let key = self.integrity_key()?;
        let records = self.records()?;
        let stored_manifest = self.get_raw(MANIFEST_KEY.as_bytes())?;
        Integrity::verify_manifest(&key, &records, stored_manifest)
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
        let active = Accounts::active()?.ok_or(NO_ACCOUNTS)?;
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

    pub(crate) fn set_integrity(&self, key: Option<[u8; 32]>) {
        if let Some(mut previous) = self.integrity.replace(key) {
            previous.zeroize();
        }
    }

    pub(crate) fn integrity_key(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.integrity
            .get()
            .ok_or_else(|| "Storage is not bound to a vault key".into())
    }

    pub(crate) fn commit(
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
