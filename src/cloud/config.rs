use crate::{
    cloud::provider::{CloudCredentials, ProviderSettings},
    core::{accounts::Accounts, storage::Storage, validation::Validation},
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

const CLOUD_CONFIG_FILE: &str = "cloud.bin";
const KEYRING_SERVICE: &str = "cortex-cloud";

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SyncRecord {
    pub last_sync_timestamp: u64,
    pub last_synced_hash: [u8; 32],
    pub entry_count: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CloudRemote {
    pub name: String,
    pub settings: ProviderSettings,
    pub fallback_credentials: Option<Vec<u8>>,
    pub accounts: BTreeMap<String, SyncRecord>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct CloudConfig {
    pub active_remote: Option<String>,
    pub remotes: BTreeMap<String, CloudRemote>,
}

impl CloudConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes =
            fs::read(&path).map_err(|error| format!("Failed to read cloud config: {error}"))?;
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let mut config: Self = Storage::decode_value(&bytes)
            .map_err(|error| format!("Invalid cloud config data: {error}"))?;

        if let Some(active) = &config.active_remote
            && !config.remotes.contains_key(active)
        {
            config.active_remote = config.remotes.keys().next().cloned();
        }

        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path()?;
        let bytes = Storage::encode_value(self)?;
        Accounts::write_atomic_file(&path, &bytes)
    }

    pub fn add_remote(
        &mut self,
        name: &str,
        settings: ProviderSettings,
        credentials: &CloudCredentials,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Validation::check_account_name(name)?;

        let mut encoded = Zeroizing::new(Storage::encode_value(credentials)?);
        let fallback = if Self::store_keyring_secret(name, &encoded).is_ok() {
            None
        } else {
            Some(encoded.as_slice().to_vec())
        };
        encoded.zeroize();

        let existing_accounts = self
            .remotes
            .get(name)
            .map_or_else(BTreeMap::new, |remote| remote.accounts.clone());

        let remote = CloudRemote {
            name: name.to_string(),
            settings,
            fallback_credentials: fallback,
            accounts: existing_accounts,
        };

        self.remotes.insert(name.to_string(), remote);
        if self.active_remote.is_none() {
            self.active_remote = Some(name.to_string());
        }

        self.save()
    }

    pub fn remove_remote(&mut self, name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let Some(mut removed) = self.remotes.remove(name) else {
            return Ok(false);
        };

        if let Some(mut fallback) = removed.fallback_credentials.take() {
            fallback.zeroize();
        }

        Self::delete_keyring_secret(name);

        if self.active_remote.as_deref() == Some(name) {
            self.active_remote = self.remotes.keys().next().cloned();
        }

        self.save()?;
        Ok(true)
    }

    pub fn set_default(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.remotes.contains_key(name) {
            return Err(format!("Cloud remote '{name}' not found.").into());
        }

        self.active_remote = Some(name.to_string());
        self.save()
    }

    pub fn resolve_remote(&self, requested: Option<&str>) -> Result<&CloudRemote, String> {
        let target = match requested {
            Some(name) => name.trim(),
            None => self.active_remote.as_deref().ok_or_else(|| {
                "No cloud remotes configured. Add one with 'cortex cloud add'.".to_string()
            })?,
        };

        self.remotes
            .get(target)
            .ok_or_else(|| format!("Cloud remote '{target}' not found."))
    }

    pub fn load_credentials(
        remote: &CloudRemote,
    ) -> Result<CloudCredentials, Box<dyn std::error::Error>> {
        if let Some(mut secret) = Self::load_keyring_secret(&remote.name) {
            let decoded = Storage::decode_value(&secret);
            secret.zeroize();
            return Ok(decoded?);
        }

        if let Some(fallback) = &remote.fallback_credentials {
            let decoded: CloudCredentials = Storage::decode_value(fallback)?;
            return Ok(decoded);
        }

        Err(format!(
            "Credentials for cloud remote '{}' were not found in the system keyring.",
            remote.name
        )
        .into())
    }

    pub fn record_sync(
        &mut self,
        remote_name: &str,
        account_name: &str,
        record: SyncRecord,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(remote) = self.remotes.get_mut(remote_name) {
            remote.accounts.insert(account_name.to_string(), record);
            self.save()?;
        }
        Ok(())
    }

    fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Accounts::cortex_dir()?.join(CLOUD_CONFIG_FILE))
    }

    fn keyring_entry(name: &str) -> Result<Entry, Box<dyn std::error::Error>> {
        Ok(Entry::new(KEYRING_SERVICE, name)?)
    }

    fn store_keyring_secret(name: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let entry = Self::keyring_entry(name)?;
        entry.set_secret(bytes)?;
        Ok(())
    }

    fn load_keyring_secret(name: &str) -> Option<Vec<u8>> {
        let entry = Self::keyring_entry(name).ok()?;
        entry.get_secret().ok()
    }

    fn delete_keyring_secret(name: &str) {
        let Ok(entry) = Self::keyring_entry(name) else {
            return;
        };
        if entry.get_secret().is_ok() {
            let _ = entry.delete_credential();
        }
    }
}
