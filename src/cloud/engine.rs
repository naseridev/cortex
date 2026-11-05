use crate::{
    core::{
        crypto::Crypto,
        integrity::Integrity,
        snapshot::Snapshot,
        storage::Storage,
        types::{PasswordEntry, SecretText},
    },
    formats::dump::Dump,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Identical,
    LocalAhead,
    RemoteAhead,
    Diverged,
}

#[derive(Default)]
pub struct SyncState {
    pub entries: Vec<(String, PasswordEntry)>,
    pub tombstones: Vec<(String, u64)>,
}

impl SyncState {
    pub fn from_storage(storage: &Storage) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            entries: storage.list_entries()?,
            tombstones: storage.list_tombstones()?,
        })
    }
}

pub struct MergeReport {
    pub entries: Vec<(String, PasswordEntry)>,
    pub tombstones: Vec<(String, u64)>,
    pub added_from_remote: usize,
    pub updated_from_remote: usize,
    pub removed_from_remote: usize,
    pub kept_local: usize,
    pub clock: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClockSkew {
    pub remote_ahead_secs: u64,
    pub vault_ahead_secs: u64,
}

impl ClockSkew {
    #[must_use]
    pub fn remote_exceeds_tolerance(&self) -> bool {
        self.remote_ahead_secs > CLOCK_SKEW_TOLERANCE_SECS
    }

    #[must_use]
    pub fn vault_exceeds_tolerance(&self) -> bool {
        self.vault_ahead_secs > CLOCK_SKEW_TOLERANCE_SECS
    }
}

#[derive(Clone, Copy)]
enum Slot<'a> {
    Live(&'a PasswordEntry),
    Deleted(u64),
}

impl Slot<'_> {
    fn timestamp(self) -> u64 {
        match self {
            Self::Live(entry) => entry.timestamp,
            Self::Deleted(deleted_at) => deleted_at,
        }
    }

    fn is_deleted(self) -> bool {
        matches!(self, Self::Deleted(_))
    }
}

fn slots(state: &SyncState) -> BTreeMap<&str, Slot<'_>> {
    let mut map: BTreeMap<&str, Slot<'_>> = state
        .entries
        .iter()
        .map(|(name, entry)| (name.as_str(), Slot::Live(entry)))
        .collect();

    for (name, deleted_at) in &state.tombstones {
        let slot = match map.get(name.as_str()).copied() {
            Some(Slot::Live(entry)) if entry.timestamp > *deleted_at => Slot::Live(entry),
            _ => Slot::Deleted(*deleted_at),
        };
        map.insert(name.as_str(), slot);
    }

    map
}

fn remote_wins(local: Slot<'_>, remote: Slot<'_>) -> bool {
    match remote.timestamp().cmp(&local.timestamp()) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => remote.is_deleted() && !local.is_deleted(),
    }
}

fn content_differs(local: &PasswordEntry, remote: &PasswordEntry) -> bool {
    local.encrypted_password != remote.encrypted_password
        || local.encrypted_description != remote.encrypted_description
        || local.encrypted_tags != remote.encrypted_tags
}

pub struct SyncEngine;

impl SyncEngine {
    #[must_use]
    pub fn digest(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    #[must_use]
    pub fn clock_skew(remote_clock: u64, local_clock: u64, now: u64) -> ClockSkew {
        ClockSkew {
            remote_ahead_secs: remote_clock.saturating_sub(now),
            vault_ahead_secs: local_clock.saturating_sub(now),
        }
    }

    #[must_use]
    pub fn evaluate_status(
        local: &SyncState,
        remote: &SyncState,
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

        let local_slots = slots(local);
        let remote_slots = slots(remote);
        let names: BTreeSet<&str> = local_slots
            .keys()
            .chain(remote_slots.keys())
            .copied()
            .collect();

        let mut local_newer = false;
        let mut remote_newer = false;

        for name in names {
            match (
                local_slots.get(name).copied(),
                remote_slots.get(name).copied(),
            ) {
                (Some(_), None) => local_newer = true,
                (None, Some(_)) => remote_newer = true,
                (None, None) => {}
                (Some(local_slot), Some(remote_slot)) => {
                    match local_slot.timestamp().cmp(&remote_slot.timestamp()) {
                        Ordering::Greater => local_newer = true,
                        Ordering::Less => remote_newer = true,
                        Ordering::Equal => match (local_slot, remote_slot) {
                            (Slot::Live(local_entry), Slot::Live(remote_entry)) => {
                                if content_differs(local_entry, remote_entry) {
                                    local_newer = true;
                                    remote_newer = true;
                                }
                            }
                            _ => {
                                if local_slot.is_deleted() && !remote_slot.is_deleted() {
                                    local_newer = true;
                                } else if remote_slot.is_deleted() && !local_slot.is_deleted() {
                                    remote_newer = true;
                                }
                            }
                        },
                    }
                }
            }
        }

        match (local_newer, remote_newer) {
            (false, false) => SyncStatus::Identical,
            (true, false) => SyncStatus::LocalAhead,
            (false, true) => SyncStatus::RemoteAhead,
            (true, true) => SyncStatus::Diverged,
        }
    }

    pub fn unpack_snapshot(snapshot: &Snapshot) -> Result<SyncState, Box<dyn std::error::Error>> {
        let mut state = SyncState::default();
        for (key, value) in snapshot.entries() {
            if let Some(name) = Storage::tombstone_name(key) {
                let deleted_at: u64 = Storage::decode_value(value)?;
                state.tombstones.push((name, deleted_at));
                continue;
            }

            if Integrity::is_reserved_key(key) {
                continue;
            }

            let name = String::from_utf8(key.clone())
                .map_err(|_| "Remote snapshot contains invalid UTF-8 entry name")?;
            let entry: PasswordEntry = Storage::decode_value(value)?;
            state.entries.push((name, entry));
        }
        state.entries.sort_by(|a, b| a.0.cmp(&b.0));
        state.tombstones.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(state)
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
        local: &SyncState,
        local_crypto: &Crypto,
        remote: &SyncState,
        remote_crypto: &Crypto,
        same_key: bool,
    ) -> Result<MergeReport, Box<dyn std::error::Error>> {
        let local_slots = slots(local);
        let remote_slots = slots(remote);
        let names: BTreeSet<&str> = local_slots
            .keys()
            .chain(remote_slots.keys())
            .copied()
            .collect();

        let mut report = MergeReport {
            entries: Vec::new(),
            tombstones: Vec::new(),
            added_from_remote: 0,
            updated_from_remote: 0,
            removed_from_remote: 0,
            kept_local: 0,
            clock: 0,
        };
        let mut clock = 0u64;

        for name in names {
            let local_slot = local_slots.get(name).copied();
            let remote_slot = remote_slots.get(name).copied();

            if let Some(newest) = local_slot
                .into_iter()
                .chain(remote_slot)
                .map(Slot::timestamp)
                .max()
            {
                clock = clock.max(newest);
            }

            let (winner, from_remote) = match (local_slot, remote_slot) {
                (Some(previous), Some(incoming)) if remote_wins(previous, incoming) => {
                    (incoming, true)
                }
                (None, Some(incoming)) => (incoming, true),
                (Some(previous), _) => (previous, false),
                (None, None) => continue,
            };

            match (from_remote, local_slot, winner) {
                (true, None, Slot::Live(_)) => report.added_from_remote += 1,
                (true, Some(_), Slot::Live(_)) => report.updated_from_remote += 1,
                (true, Some(previous), Slot::Deleted(_)) if !previous.is_deleted() => {
                    report.removed_from_remote += 1;
                }
                (false, _, _) if remote_slot.is_some() => report.kept_local += 1,
                _ => {}
            }

            match winner {
                Slot::Live(entry) => {
                    let kept = if from_remote {
                        Self::rebind_entry(name, entry, remote_crypto, local_crypto, same_key)?
                    } else {
                        entry.clone()
                    };
                    report.entries.push((name.to_string(), kept));
                }
                Slot::Deleted(deleted_at) => {
                    report.tombstones.push((name.to_string(), deleted_at));
                }
            }
        }

        report.clock = clock;
        Ok(report)
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
