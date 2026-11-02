use crate::core::storage::{Storage, decode_value, encode_value};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const CONFIG_KEY: &[u8] = b"__config__";

static CONFIG_CACHE: Mutex<Option<Config>> = Mutex::new(None);

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub session_timeout_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_timeout_seconds: 480,
        }
    }
}

impl Config {
    pub fn load_from_db(storage: &Storage) -> Result<Self, Box<dyn std::error::Error>> {
        let config = if let Some(data) = storage.get_raw(CONFIG_KEY)? {
            decode_value::<Config>(&data)
                .map_err(|error| format!("Invalid configuration data: {error}"))?
        } else {
            let default_config = Self::default();
            default_config.save_to_db(storage)?;
            default_config
        };

        Self::update_cache(config.clone())?;
        Ok(config)
    }

    pub fn save_to_db(&self, storage: &Storage) -> Result<(), Box<dyn std::error::Error>> {
        storage.put_raw(CONFIG_KEY, &encode_value(self)?)?;
        Self::update_cache(self.clone())
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(cached) = Self::get_cached() {
            return Ok(cached);
        }

        if !Storage::database_exists()? {
            return Ok(Self::default());
        }

        let storage = Storage::new()?;
        Self::load_from_db(&storage)
    }

    fn update_cache(config: Config) -> Result<(), Box<dyn std::error::Error>> {
        let mut cached = CONFIG_CACHE
            .lock()
            .map_err(|_| "Failed to acquire cache lock")?;
        *cached = Some(config);

        Ok(())
    }

    fn get_cached() -> Option<Config> {
        let cached = CONFIG_CACHE.lock().ok()?;
        cached.clone()
    }

    pub fn clear_cache() {
        if let Ok(mut cached) = CONFIG_CACHE.lock() {
            *cached = None;
        }
    }
}
