use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_session_timeout")]
    pub session_timeout_seconds: u64,

    #[serde(default = "default_hardware_binding")]
    pub hardware_binding_enabled: bool,
}

fn default_session_timeout() -> u64 {
    480
}

fn default_hardware_binding() -> bool {
    false
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_timeout_seconds: 480,
            hardware_binding_enabled: false,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::get_config_path();

        if !config_path.exists() {
            let default_config = Self::default();
            default_config.save()?;
            return Ok(default_config);
        }

        let mut file = File::open(&config_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let config: Config = toml::from_str(&contents).unwrap_or_else(|_| Self::default());

        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::get_config_path();

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_string = toml::to_string_pretty(self)?;
        let mut file = File::create(&config_path)?;
        file.write_all(toml_string.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn get_config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("cortex");
        fs::create_dir_all(&path).ok();
        path.push("config.toml");
        path
    }
}
