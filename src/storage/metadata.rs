use crate::{
    domain::types::PasswordEntry,
    security::crypto::Crypto,
    storage::{
        Storage,
        engine::{CLOCK_KEY, FAILED_ATTEMPTS_KEY, INIT_MARKER, SALT_KEY},
        integrity::{Changes, Integrity},
    },
};

impl Storage {
    pub fn init_db(&self, crypto: &Crypto, salt: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.bind_integrity(crypto);
        self.commit(
            &Changes::new(),
            &Self::initialization_metadata(crypto, salt),
        )
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

    pub(crate) fn initialization_metadata(
        crypto: &Crypto,
        salt: &[u8],
    ) -> [(&'static str, Vec<u8>); 2] {
        [
            (INIT_MARKER, crypto.verification()),
            (SALT_KEY, salt.to_vec()),
        ]
    }
}
