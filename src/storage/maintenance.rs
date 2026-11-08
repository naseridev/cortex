use crate::{
    domain::types::PasswordEntry,
    formats::dump::DumpFile,
    security::crypto::Crypto,
    storage::{
        Snapshot, Storage,
        engine::{CLOCK_KEY, FAILED_ATTEMPTS_KEY, VAULT},
        integrity::{Changes, Integrity},
    },
};
use std::path::{Path, PathBuf};

impl Storage {
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
}
