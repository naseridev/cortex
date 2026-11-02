use crate::{
    core::{
        crypto::Crypto,
        password::{Password, PasswordCharset},
        platform,
        storage::{Storage, decode_value, encode_value},
    },
    mcp::config::McpConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const ACCOUNTS_FILE: &str = "accounts.bin";
const AGENT_MASTER_PASSWORD_LENGTH: usize = 32;

#[derive(Serialize, Deserialize, Default, Clone)]
struct AccountRegistry {
    active: Option<String>,
    accounts: Vec<String>,
    #[serde(default)]
    agent_keys: BTreeMap<String, [u8; 32]>,
}

#[derive(Serialize, Deserialize, Default)]
struct LegacyAccountRegistry {
    active: Option<String>,
    accounts: Vec<String>,
}

pub struct Accounts;

impl Accounts {
    pub fn cortex_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut path =
            platform::config_dir().ok_or("Could not determine the configuration directory")?;
        path.push("cortex");

        fs::create_dir_all(&path)
            .map_err(|error| format!("Failed to create directory {}: {error}", path.display()))?;
        platform::restrict_to_owner(&path)
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

    pub fn is_agent(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok(registry.agent_keys.contains_key(name) && Self::db_file_exists(name)?)
    }

    pub fn get_agent_key(name: &str) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok(registry.agent_keys.get(name).copied())
    }

    pub fn update_agent_key(name: &str, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;
        if registry.accounts.iter().any(|account| account == name) {
            registry.agent_keys.insert(name.to_string(), *key);
            Self::save_registry(&registry)?;
        }
        Ok(())
    }

    pub fn list_agents() -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok(registry
            .accounts
            .into_iter()
            .filter(|name| registry.agent_keys.contains_key(name))
            .collect())
    }

    pub fn create_agent(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if Self::exists(name)? {
            return Err(format!("Account '{name}' already exists.").into());
        }

        let charset = PasswordCharset::from_bits(
            PasswordCharset::UPPERCASE
                | PasswordCharset::LOWERCASE
                | PasswordCharset::DIGITS
                | PasswordCharset::SPECIAL,
        );

        let generated = Zeroizing::new(Password::generate(AGENT_MASTER_PASSWORD_LENGTH, charset)?);
        let (crypto, salt) = Crypto::create(&generated)?;

        let storage = Storage::open_account(name)?;
        storage.init_db(&crypto, &salt)?;
        drop(storage);

        let mut registry = Self::load_registry()?;
        if !registry.accounts.iter().any(|account| account == name) {
            registry.accounts.push(name.to_string());
            registry.accounts.sort();
        }

        registry.agent_keys.insert(name.to_string(), *crypto.key());

        if registry.active.is_none() {
            registry.active = Some(name.to_string());
        }

        Self::save_registry(&registry)
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

        platform::restrict_to_owner(&new_path).map_err(|error| {
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

        if let Some(key) = registry.agent_keys.remove(old_name) {
            registry.agent_keys.insert(new_name.to_string(), key);
        }

        if registry.active.as_deref() == Some(old_name) {
            registry.active = Some(new_name.to_string());
        }

        Self::save_registry(&registry)?;

        if McpConfig::is_initialized()?
            && let Ok(mut mcp_config) = McpConfig::load()
            && mcp_config.active_agent_account.as_deref() == Some(old_name)
        {
            mcp_config.active_agent_account = Some(new_name.to_string());
            let _ = mcp_config.save();
        }

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
        if let Some(mut key) = registry.agent_keys.remove(name) {
            key.zeroize();
        }

        let was_active = registry.active.as_deref() == Some(name);
        if was_active {
            registry.active = registry.accounts.first().cloned();
        }

        Self::save_registry(&registry)?;

        if McpConfig::is_initialized()?
            && let Ok(mut mcp_config) = McpConfig::load()
            && mcp_config.active_agent_account.as_deref() == Some(name)
        {
            mcp_config.active_agent_account = registry
                .accounts
                .iter()
                .find(|acc| registry.agent_keys.contains_key(*acc))
                .cloned();
            let _ = mcp_config.save();
        }

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

        platform::restrict_to_owner(temp.path())
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

        let mut registry: AccountRegistry = if let Ok(reg) = decode_value(&bytes) {
            reg
        } else {
            let legacy: LegacyAccountRegistry = decode_value(&bytes)
                .map_err(|error| format!("Invalid accounts registry data: {error}"))?;
            AccountRegistry {
                active: legacy.active,
                accounts: legacy.accounts,
                agent_keys: BTreeMap::new(),
            }
        };

        let mut valid_accounts = Vec::with_capacity(registry.accounts.len());
        for name in registry.accounts {
            if Self::db_file_exists(&name)? && !valid_accounts.contains(&name) {
                valid_accounts.push(name);
            }
        }

        valid_accounts.sort();
        registry
            .agent_keys
            .retain(|name, _| valid_accounts.contains(name));
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
        let bytes = encode_value(registry)?;
        Self::write_atomic_file(&path, &bytes)
    }
}
