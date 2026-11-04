use crate::core::{
    crypto::Crypto,
    dump::Dump,
    integrity::Integrity,
    snapshot::Snapshot,
    storage::Storage,
    types::{PasswordEntry, SecretText},
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Identical,
    LocalAhead,
    RemoteAhead,
    Diverged,
}

pub struct MergeReport {
    pub entries: Vec<(String, PasswordEntry)>,
    pub added_from_remote: usize,
    pub updated_from_remote: usize,
    pub kept_local: usize,
}

pub struct SyncEngine;

impl SyncEngine {
    #[must_use]
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    #[must_use]
    pub fn evaluate_status(
        local_entries: &[(String, PasswordEntry)],
        remote_entries: &[(String, PasswordEntry)],
        last_synced_hash: Option<[u8; 32]>,
        local_hash: [u8; 32],
        remote_hash: [u8; 32],
    ) -> SyncStatus {
        if local_hash == remote_hash {
            return SyncStatus::Identical;
        }

        if let Some(base_hash) = last_synced_hash {
            if local_hash == base_hash {
                return SyncStatus::RemoteAhead;
            }
            if remote_hash == base_hash {
                return SyncStatus::LocalAhead;
            }
        }

        let local_map: BTreeMap<&str, &PasswordEntry> =
            local_entries.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let remote_map: BTreeMap<&str, &PasswordEntry> = remote_entries
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();

        let mut local_newer = false;
        let mut remote_newer = false;

        for (name, local_entry) in &local_map {
            match remote_map.get(name) {
                Some(remote_entry) => {
                    if local_entry.timestamp > remote_entry.timestamp {
                        local_newer = true;
                    } else if remote_entry.timestamp > local_entry.timestamp {
                        remote_newer = true;
                    } else if local_entry.encrypted_password != remote_entry.encrypted_password
                        || local_entry.encrypted_description != remote_entry.encrypted_description
                        || local_entry.encrypted_tags != remote_entry.encrypted_tags
                    {
                        local_newer = true;
                        remote_newer = true;
                    }
                }
                None => local_newer = true,
            }
        }

        for name in remote_map.keys() {
            if !local_map.contains_key(name) {
                remote_newer = true;
            }
        }

        match (local_newer, remote_newer) {
            (false, false) => SyncStatus::Identical,
            (true, false) => SyncStatus::LocalAhead,
            (false, true) => SyncStatus::RemoteAhead,
            (true, true) => SyncStatus::Diverged,
        }
    }

    pub fn unpack_snapshot(
        snapshot: &Snapshot,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();
        for (key, value) in snapshot.entries() {
            if Integrity::is_reserved_key(key) {
                continue;
            }
            let name = String::from_utf8(key.clone())
                .map_err(|_| "Remote snapshot contains invalid UTF-8 entry name")?;
            let entry: PasswordEntry = Storage::decode_value(value)?;
            entries.push((name, entry));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    pub fn open_remote_snapshot(
        remote_bytes: &[u8],
        local_crypto: &Crypto,
        prompt_password: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn std::error::Error>>,
    ) -> Result<(Snapshot, Crypto, bool), Box<dyn std::error::Error>> {
        let dump_file = Dump::decode(remote_bytes)?;

        if let Ok(snapshot) = Storage::read_dump(&dump_file, local_crypto) {
            let key_copy = *local_crypto.key();
            return Ok((snapshot, Crypto::from_key(key_copy), true));
        }

        let password = prompt_password()?;
        let remote_crypto = Crypto::open(&password, &dump_file.salt)?;
        let snapshot = Storage::read_dump(&dump_file, &remote_crypto)?;

        Ok((snapshot, remote_crypto, false))
    }

    pub fn merge(
        local_entries: &[(String, PasswordEntry)],
        local_crypto: &Crypto,
        remote_entries: &[(String, PasswordEntry)],
        remote_crypto: &Crypto,
        same_key: bool,
    ) -> Result<MergeReport, Box<dyn std::error::Error>> {
        let mut merged_map: BTreeMap<String, PasswordEntry> =
            local_entries.iter().cloned().collect();

        let mut added_from_remote = 0usize;
        let mut updated_from_remote = 0usize;
        let mut kept_local = 0usize;

        for (name, remote_entry) in remote_entries {
            match merged_map.get(name) {
                None => {
                    let converted = Self::rebind_entry(
                        name,
                        remote_entry,
                        remote_crypto,
                        local_crypto,
                        same_key,
                    )?;
                    merged_map.insert(name.clone(), converted);
                    added_from_remote += 1;
                }
                Some(local_entry) => {
                    if remote_entry.timestamp > local_entry.timestamp {
                        let converted = Self::rebind_entry(
                            name,
                            remote_entry,
                            remote_crypto,
                            local_crypto,
                            same_key,
                        )?;
                        merged_map.insert(name.clone(), converted);
                        updated_from_remote += 1;
                    } else {
                        kept_local += 1;
                    }
                }
            }
        }

        let entries: Vec<(String, PasswordEntry)> = merged_map.into_iter().collect();

        Ok(MergeReport {
            entries,
            added_from_remote,
            updated_from_remote,
            kept_local,
        })
    }

    fn rebind_entry(
        name: &str,
        entry: &PasswordEntry,
        source_crypto: &Crypto,
        target_crypto: &Crypto,
        same_key: bool,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        if same_key {
            return Ok(entry.clone());
        }

        let raw_password = source_crypto.decrypt_entry(name, entry)?;
        let password = Zeroizing::new(SecretText::decode(raw_password)?);
        let description = source_crypto.decrypt_description(name, entry)?;
        let tags = source_crypto.decrypt_tags(name, entry)?;
        let tag_slice = (!tags.is_empty()).then_some(tags.as_slice());

        let mut reencrypted = target_crypto.create_entry(
            name,
            password.as_bytes(),
            description.as_deref(),
            tag_slice,
        )?;
        reencrypted.timestamp = entry.timestamp;
        Ok(reencrypted)
    }
}
