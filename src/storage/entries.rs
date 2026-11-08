use crate::{
    domain::{limits::MAX_ENTRIES, types::PasswordEntry},
    storage::{
        Storage,
        engine::{CLOCK_KEY, TOMBSTONE_PREFIX},
        integrity::{Changes, Integrity},
    },
    system::time::Time,
};

const MAX_SEARCH_PATTERN_BYTES: usize = 100;

impl Storage {
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

    pub(crate) fn tombstone_key(name: &str) -> Vec<u8> {
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
}
