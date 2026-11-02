use crate::core::{config::Config, storage::Storage, time::Time};
use keyring::Entry;
use zeroize::Zeroize;

const SERVICE_NAME: &str = "cortex";
const ACCOUNT_NAME: &str = "vault-session";
const MAX_SESSION_AGE: u64 = 86400;
const TIMESTAMP_BYTES: usize = 8;
const KEY_BYTES: usize = 32;
const RECORD_BYTES: usize = TIMESTAMP_BYTES + KEY_BYTES;

pub struct Session;

impl Session {
    fn entry() -> Result<Entry, Box<dyn std::error::Error>> {
        Ok(Entry::new(SERVICE_NAME, ACCOUNT_NAME)?)
    }

    pub fn save_session(vault_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = [0u8; RECORD_BYTES];

        record[..TIMESTAMP_BYTES].copy_from_slice(&Time::current_timestamp().to_le_bytes());
        record[TIMESTAMP_BYTES..].copy_from_slice(vault_key);

        let stored = Self::entry()?.set_secret(&record);

        record.zeroize();
        stored?;

        Ok(())
    }

    pub fn load_session(storage: &Storage) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        let Ok(entry) = Self::entry() else {
            return Ok(None);
        };

        let Ok(mut record) = entry.get_secret() else {
            return Ok(None);
        };

        if record.len() != RECORD_BYTES {
            record.zeroize();
            Self::clear_session()?;
            return Ok(None);
        }

        let mut timestamp_bytes = [0u8; TIMESTAMP_BYTES];
        timestamp_bytes.copy_from_slice(&record[..TIMESTAMP_BYTES]);

        let timestamp = u64::from_le_bytes(timestamp_bytes);
        let mut key = [0u8; KEY_BYTES];

        key.copy_from_slice(&record[TIMESTAMP_BYTES..]);
        record.zeroize();

        let config = Config::load_from_db(storage)?;
        let elapsed = Time::current_timestamp().saturating_sub(timestamp);

        if elapsed > config.session_timeout_seconds || elapsed > MAX_SESSION_AGE {
            key.zeroize();
            Self::clear_session()?;
            return Ok(None);
        }

        Ok(Some(key))
    }

    pub fn clear_session() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(entry) = Self::entry() else {
            return Ok(());
        };

        if entry.get_secret().is_err() {
            return Ok(());
        }

        entry.delete_credential()?;
        Ok(())
    }
}
