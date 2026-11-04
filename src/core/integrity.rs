use crate::core::storage::{RESERVED_PREFIX, TOMBSTONE_PREFIX};
use std::collections::BTreeMap;

pub(crate) const MANIFEST_KEY: &str = "__manifest__";
pub(crate) const INTEGRITY_FAILED_MESSAGE: &str = "Database integrity check failed. Stored data was modified, replaced or removed outside of cortex.";
pub(crate) const LEGACY_VAULT_MESSAGE: &str =
    "This vault predates integrity protection. Run 'reset' once to upgrade it.";

pub(crate) type Changes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
pub(crate) type Records = Vec<(Vec<u8>, Vec<u8>)>;

pub(crate) struct Integrity;

impl Integrity {
    #[must_use]
    pub(crate) fn is_reserved_name(name: &str) -> bool {
        name.starts_with(RESERVED_PREFIX)
    }

    #[must_use]
    pub(crate) fn is_reserved_key(key: &[u8]) -> bool {
        key.starts_with(RESERVED_PREFIX.as_bytes())
    }

    #[must_use]
    pub(crate) fn is_tombstone_key(key: &[u8]) -> bool {
        key.starts_with(TOMBSTONE_PREFIX.as_bytes())
    }

    #[must_use]
    fn is_meta_key(key: &[u8]) -> bool {
        Self::is_reserved_key(key) && !Self::is_tombstone_key(key)
    }

    pub(crate) fn verify_manifest(
        key: &[u8; 32],
        records: &[(Vec<u8>, Vec<u8>)],
        stored_manifest: Option<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = Self::digest_records(key, records, &Changes::new());

        match stored_manifest {
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
                if records.iter().any(|(name, _)| !Self::is_reserved_key(name)) {
                    Err(LEGACY_VAULT_MESSAGE.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn digest_records(
        key: &[u8; 32],
        records: &[(Vec<u8>, Vec<u8>)],
        changes: &Changes,
    ) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_keyed(key);
        let mut pending = changes.iter().peekable();

        for (db_key, db_value) in records {
            if Self::is_meta_key(db_key) {
                continue;
            }

            while let Some((change_key, change_value)) =
                pending.next_if(|(name, _)| name.as_slice() < db_key.as_slice())
            {
                Self::feed_change(&mut hasher, change_key, change_value.as_deref());
            }

            match pending.next_if(|(name, _)| name.as_slice() == db_key.as_slice()) {
                Some((change_key, change_value)) => {
                    Self::feed_change(&mut hasher, change_key, change_value.as_deref());
                }
                None => Self::feed_record(&mut hasher, db_key, db_value),
            }
        }

        for (change_key, change_value) in pending {
            Self::feed_change(&mut hasher, change_key, change_value.as_deref());
        }

        hasher.finalize()
    }

    #[must_use]
    pub(crate) fn snapshot_digest(key: &[u8; 32], entries: &[(Vec<u8>, Vec<u8>)]) -> blake3::Hash {
        let mut records: Vec<&(Vec<u8>, Vec<u8>)> = entries
            .iter()
            .filter(|(name, _)| !Self::is_meta_key(name))
            .collect();

        records.sort_by(|left, right| left.0.cmp(&right.0));

        let mut hasher = blake3::Hasher::new_keyed(key);
        for (name, value) in records {
            Self::feed_record(&mut hasher, name, value);
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
            Self::feed_record(hasher, name, value);
        }
    }
}
