use crate::{
    core::{
        crypto::Crypto,
        password::{Password, PasswordCharset},
        platform::Platform,
        storage::Storage,
    },
    mcp::config::McpConfig,
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const ACCOUNTS_FILE: &str = "accounts.bin";
const AGENT_KEYRING_SERVICE: &str = "cortex-agent";
const AGENT_WRAP_CONTEXT: &str = "cortex agent local key wrap v1";
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

    pub fn is_agent(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        Ok(registry.agent_keys.contains_key(name) && Self::db_file_exists(name)?)
    }

    pub fn get_agent_key(name: &str) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
        let registry = Self::load_registry()?;
        let Some(stored) = registry.agent_keys.get(name).copied() else {
            return Ok(None);
        };

        if let Some(keyring_key) = Self::load_keyring_agent_key(name) {
            return Ok(Some(keyring_key));
        }

        if stored == [0u8; 32] {
            return Ok(None);
        }

        Ok(Some(Self::xor_agent_mask(name, &stored)?))
    }

    pub fn update_agent_key(name: &str, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = Self::load_registry()?;
        if registry.accounts.iter().any(|account| account == name) {
            let fallback = Self::persist_agent_secret(name, key)?;
            registry.agent_keys.insert(name.to_string(), fallback);
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

        let fallback = Self::persist_agent_secret(name, crypto.key())?;
        registry.agent_keys.insert(name.to_string(), fallback);

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

        let agent_key = Self::get_agent_key(old_name)?;

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

        if let Some(mut old_stored) = registry.agent_keys.remove(old_name) {
            old_stored.zeroize();
            Self::delete_keyring_agent_key(old_name);
            if let Some(mut resolved_key) = agent_key {
                let fallback = Self::persist_agent_secret(new_name, &resolved_key)?;
                resolved_key.zeroize();
                registry.agent_keys.insert(new_name.to_string(), fallback);
            }
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
        Self::delete_keyring_agent_key(name);

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

        Platform::restrict_to_owner(temp.path())
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;
        temp.persist(path)
            .map_err(|error| format!("Failed to save {}: {}", path.display(), error.error))?;

        Ok(())
    }

    fn persist_agent_secret(
        name: &str,
        key: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let wrapped = Self::xor_agent_mask(name, key)?;
        let _ = Self::store_keyring_agent_key(name, key);
        if Self::load_keyring_agent_key(name).as_ref() == Some(key) {
            Ok([0u8; 32])
        } else {
            Ok(wrapped)
        }
    }

    fn xor_agent_mask(
        name: &str,
        input: &[u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let dir = Self::cortex_dir()?;
        let mut material = Vec::new();
        material.extend_from_slice(dir.to_string_lossy().as_bytes());
        material.push(0);
        material.extend_from_slice(name.as_bytes());

        let mut mask = blake3::derive_key(AGENT_WRAP_CONTEXT, &material);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = input[i] ^ mask[i];
        }
        mask.zeroize();
        Ok(out)
    }

    fn store_keyring_agent_key(
        name: &str,
        key: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entry = Entry::new(AGENT_KEYRING_SERVICE, name)?;
        entry.set_secret(key)?;
        Ok(())
    }

    fn load_keyring_agent_key(name: &str) -> Option<[u8; 32]> {
        let entry = Entry::new(AGENT_KEYRING_SERVICE, name).ok()?;
        let mut secret = entry.get_secret().ok()?;
        let parsed = <[u8; 32]>::try_from(secret.as_slice()).ok();
        secret.zeroize();
        parsed
    }

    fn delete_keyring_agent_key(name: &str) {
        if let Ok(entry) = Entry::new(AGENT_KEYRING_SERVICE, name)
            && entry.get_secret().is_ok()
        {
            let _ = entry.delete_credential();
        }
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
            let legacy: LegacyAccountRegistry = Storage::decode_value(&bytes)
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
        let bytes = Storage::encode_value(registry)?;
        Self::write_atomic_file(&path, &bytes)
    }
}
