use crate::core::{config::Config, time::Time};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const SERVICE_NAME: &str = "cortex";
const ACCOUNT_NAME: &str = "vault-session";
const MAX_SESSION_AGE: u64 = 86400;

#[derive(Serialize, Deserialize)]
struct SessionData {
    timestamp: u64,
    key: [u8; 32],
}

impl Drop for SessionData {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct Session;

impl Session {
    fn entry() -> Result<Entry, Box<dyn std::error::Error>> {
        Ok(Entry::new(SERVICE_NAME, ACCOUNT_NAME)?)
    }

    pub fn save_session(vault_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let data = SessionData {
            timestamp: Time::current_timestamp(),
            key: *vault_key,
        };
        let mut serialized = bincode::serialize(&data)?;
        let stored = Self::entry()?.set_secret(&serialized);
        serialized.zeroize();
        stored?;
        Ok(())
    }

    pub fn load_session() -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        let Ok(entry) = Self::entry() else {
            return Ok(None);
        };
        let Ok(mut serialized) = entry.get_secret() else {
            return Ok(None);
        };
        let decoded = bincode::deserialize::<SessionData>(&serialized);
        serialized.zeroize();
        let Ok(session) = decoded else {
            Self::clear_session()?;
            return Ok(None);
        };

        let config = Config::load()?;
        let elapsed = Time::current_timestamp().saturating_sub(session.timestamp);
        if elapsed > config.session_timeout_seconds || elapsed > MAX_SESSION_AGE {
            Self::clear_session()?;
            return Ok(None);
        }

        Ok(Some(session.key))
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
