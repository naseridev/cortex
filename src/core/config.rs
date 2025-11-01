use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};

const CONFIG_KEY: &str = "__config__";

static CONFIG_CACHE: OnceLock<Arc<Mutex<Option<Config>>>> = OnceLock::new();

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_session_timeout")]
    pub session_timeout_seconds: u64,
}

fn default_session_timeout() -> u64 {
    480
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_timeout_seconds: 480,
        }
    }
}

impl Config {
    pub fn load_from_db(db: &sled::Db) -> Result<Self, Box<dyn std::error::Error>> {
        match db.get(CONFIG_KEY)? {
            Some(data) => {
                let config: Config =
                    bincode::deserialize(&data).unwrap_or_else(|_| Self::default());

                Self::update_cache(config.clone())?;
                Ok(config)
            }
            None => {
                let default_config = Self::default();
                default_config.save_to_db(db)?;
                Self::update_cache(default_config.clone())?;
                Ok(default_config)
            }
        }
    }

    pub fn save_to_db(&self, db: &sled::Db) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = bincode::serialize(self)?;
        db.insert(CONFIG_KEY, serialized)?;
        db.flush()?;
        Self::update_cache(self.clone())?;
        Ok(())
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(cached) = Self::get_cached() {
            return Ok(cached);
        }

        use crate::core::storage::Storage;

        if !Storage::database_exists() {
            return Ok(Self::default());
        }

        let storage = Storage::new()?;
        Self::load_from_db(&storage.db)
    }

    fn update_cache(config: Config) -> Result<(), Box<dyn std::error::Error>> {
        let cache = CONFIG_CACHE.get_or_init(|| Arc::new(Mutex::new(None)));
        let mut cached = cache.lock().map_err(|_| "Failed to acquire cache lock")?;
        *cached = Some(config);
        Ok(())
    }

    fn get_cached() -> Option<Config> {
        CONFIG_CACHE
            .get()
            .and_then(|cache| cache.lock().ok())
            .and_then(|cached| cached.clone())
    }

    pub fn clear_cache() {
        if let Some(cache) = CONFIG_CACHE.get() {
            if let Ok(mut cached) = cache.lock() {
                *cached = None;
            }
        }
    }
}
