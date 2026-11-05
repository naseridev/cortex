use crate::core::{platform::Platform, storage::Storage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const ACCOUNTS_FILE: &str = "accounts.bin";
pub const NO_ACCOUNTS: &str = "No accounts found. Create one with 'account create'.";

#[derive(Serialize, Deserialize, Default, Clone)]
struct AccountRegistry {
    active: Option<String>,
    accounts: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct LegacyAgentAccountRegistry {
    active: Option<String>,
    accounts: Vec<String>,
    #[serde(default)]
    agent_keys: BTreeMap<String, [u8; 32]>,
}

pub struct Accounts;

impl Accounts {
    pub fn cortex_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut path =
            Platform::config_dir().ok_or("Could not determine the configuration directory")?;
        path.push("cortex");

        fs::create_dir_all(&path)
            .map_err(|error| format!("Failed to create directory {}: {error}", path.display()))?;
        Platform::restrict_to_owner(&path)
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;

        Ok(path)
    }

    #[must_use]
    pub fn file_name(name: &str) -> String {
        let hash = blake3::hash(name.as_bytes());
        format!("{}.redb", hash.to_hex())
    }

    pub fn db_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut path = Self::cortex_dir()?;
        path.push(Self::file_name(name));
        Ok(path)
    }

    pub fn active() -> Result<Option<String>, Box<dyn std::error::Error>> {
        Ok(Self::load_registry()?.active)
    }

    pub fn exists(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok(registry.accounts.iter().any(|account| account == name) && Self::db_file_exists(name)?)
    }

    pub fn list() -> Result<(Vec<String>, Option<String>), Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok((registry.accounts, registry.active))
    }

    pub fn register(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;
        if !registry.accounts.iter().any(|account| account == name) {
            registry.accounts.push(name.to_string());
            registry.accounts.sort();
        }

        registry.active = Some(name.to_string());
        Self::save_registry(&registry)
    }

    pub fn switch(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;

        if !registry.accounts.iter().any(|account| account == name) {
            return Err(format!("Account '{name}' not found.").into());
        }

        registry.active = Some(name.to_string());
        Self::save_registry(&registry)
    }

    pub fn rename(old_name: &str, new_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;

        if !registry.accounts.iter().any(|name| name == old_name) {
            return Err(format!("Account '{old_name}' not found.").into());
        }

        if registry.accounts.iter().any(|name| name == new_name) || Self::db_file_exists(new_name)?
        {
            return Err(format!("Account '{new_name}' already exists.").into());
        }

        let old_path = Self::db_path(old_name)?;
        let new_path = Self::db_path(new_name)?;

        fs::rename(&old_path, &new_path).map_err(|error| {
            format!("Failed to rename database from '{old_name}' to '{new_name}': {error}")
        })?;

        Platform::restrict_to_owner(&new_path).map_err(|error| {
            format!(
                "Failed to set permissions on {}: {error}",
                new_path.display()
            )
        })?;

        for account in &mut registry.accounts {
            if account == old_name {
                *account = new_name.to_string();
            }
        }

        registry.accounts.sort();

        if registry.active.as_deref() == Some(old_name) {
            registry.active = Some(new_name.to_string());
        }

        Self::save_registry(&registry)?;

        Ok(())
    }

    pub fn delete(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;

        if !registry.accounts.iter().any(|account| account == name) {
            return Err(format!("Account '{name}' not found.").into());
        }

        let db_path = Self::db_path(name)?;
        if db_path.exists() {
            fs::remove_file(&db_path).map_err(|error| {
                format!("Failed to delete database for account '{name}': {error}")
            })?;
        }

        registry.accounts.retain(|account| account != name);

        let was_active = registry.active.as_deref() == Some(name);
        if was_active {
            registry.active = registry.accounts.first().cloned();
        }

        Self::save_registry(&registry)?;

        Ok(was_active)
    }

    pub fn db_file_exists(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let db_path = Self::db_path(name)?;
        Ok(fs::metadata(&db_path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
    }

    pub(crate) fn write_atomic_file(
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = path.parent().unwrap_or(Path::new("."));

        let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            format!(
                "Failed to create temporary file in {}: {error}",
                directory.display()
            )
        })?;

        temp.write_all(bytes)
            .map_err(|error| format!("Failed to write {}: {error}", path.display()))?;
        temp.as_file()
            .sync_all()
            .map_err(|error| format!("Failed to sync {}: {error}", path.display()))?;

        Platform::restrict_to_owner(temp.path())
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;
        temp.persist(path)
            .map_err(|error| format!("Failed to save {}: {}", path.display(), error.error))?;

        Ok(())
    }

    fn registry_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Self::cortex_dir()?.join(ACCOUNTS_FILE))
    }

    fn load_registry() -> Result<AccountRegistry, Box<dyn std::error::Error>> {
        let path = Self::registry_path()?;
        if !path.exists() {
            return Ok(AccountRegistry::default());
        }

        let bytes = fs::read(&path)
            .map_err(|error| format!("Failed to read accounts registry: {error}"))?;
        if bytes.is_empty() {
            return Ok(AccountRegistry::default());
        }

        let mut registry: AccountRegistry = if let Ok(reg) = Storage::decode_value(&bytes) {
            reg
        } else {
            let legacy: LegacyAgentAccountRegistry = Storage::decode_value(&bytes)
                .map_err(|error| format!("Invalid accounts registry data: {error}"))?;
            AccountRegistry {
                active: legacy.active,
                accounts: legacy.accounts,
            }
        };

        let mut valid_accounts = Vec::with_capacity(registry.accounts.len());
        for name in registry.accounts {
            if Self::db_file_exists(&name)? && !valid_accounts.contains(&name) {
                valid_accounts.push(name);
            }
        }

        valid_accounts.sort();
        registry.accounts = valid_accounts;

        let active_is_valid = registry
            .active
            .as_ref()
            .is_some_and(|active| registry.accounts.contains(active));

        if !active_is_valid {
            registry.active = registry.accounts.first().cloned();
        }

        Ok(registry)
    }

    fn save_registry(registry: &AccountRegistry) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::registry_path()?;
        let bytes = Storage::encode_value(registry)?;
        Self::write_atomic_file(&path, &bytes)
    }
}
