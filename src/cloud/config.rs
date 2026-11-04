use crate::{
    cloud::provider::{CloudCredentials, ProviderSettings},
    core::{
        accounts::Accounts, crypto::Crypto, password::Password, storage::Storage,
        validation::Validation,
    },
    ui::prompt::UserPrompt,
};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

const CLOUD_CONFIG_FILE: &str = "cloud.bin";
const KEYRING_SERVICE: &str = "cortex-cloud";
const CLOUD_PASSPHRASE_PROMPT: &str = "Cloud credentials passphrase: ";
const NEW_CLOUD_PASSPHRASE_PROMPT: &str =
    "Keyring unavailable. Choose a cloud credentials passphrase: ";
const CONFIRM_CLOUD_PASSPHRASE_PROMPT: &str = "Confirm cloud credentials passphrase: ";
const FALLBACK_FORMAT_ERROR: &str =
    "Stored cloud credentials use an unsupported format. Remove the remote and add it again.";
const FALLBACK_DECRYPT_ERROR: &str =
    "Could not decrypt the stored cloud credentials. Check the cloud credentials passphrase.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStorage {
    Keyring,
    Passphrase,
    NoSecret,
}

type StoredCredentials = (Option<Vec<u8>>, CredentialStorage);

#[derive(Serialize, Deserialize)]
struct SealedCredentials {
    kdf: Vec<u8>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

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
    ) -> Result<CredentialStorage, Box<dyn std::error::Error>> {
        Validation::check_account_name(name)?;

        let (fallback_credentials, storage) = Self::store_credentials(name, credentials)?;

        let existing_accounts = self
            .remotes
            .get(name)
            .map_or_else(BTreeMap::new, |remote| remote.accounts.clone());

        let remote = CloudRemote {
            name: name.to_string(),
            settings,
            fallback_credentials,
            accounts: existing_accounts,
        };

        self.remotes.insert(name.to_string(), remote);
        if self.active_remote.is_none() {
            self.active_remote = Some(name.to_string());
        }

        self.save()?;
        Ok(storage)
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
        Self::load_credentials_from(remote, Self::load_keyring_secret, prompt_cloud_passphrase)
    }

    pub fn load_credentials_from(
        remote: &CloudRemote,
        keyring: impl FnOnce(&str) -> Option<Vec<u8>>,
        prompt: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn std::error::Error>>,
    ) -> Result<CloudCredentials, Box<dyn std::error::Error>> {
        if let Some(mut secret) = keyring(&remote.name) {
            let decoded: Result<CloudCredentials, String> = Storage::decode_value(&secret);
            secret.zeroize();
            return Ok(decoded?);
        }

        match remote.fallback_credentials.as_deref() {
            None => Err(format!(
                "Credentials for cloud remote '{}' were not found in the system keyring.",
                remote.name
            )
            .into()),
            Some([]) => Ok(CloudCredentials::default()),
            Some(bytes) => {
                Self::parse_sealed(bytes)?;
                let passphrase = prompt()?;
                Self::open_credentials(bytes, &passphrase)
            }
        }
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

    #[must_use]
    pub fn holds_no_secret(credentials: &CloudCredentials) -> bool {
        [
            &credentials.token,
            &credentials.refresh_token,
            &credentials.client_id,
            &credentials.client_secret,
            &credentials.access_key,
            &credentials.secret_key,
            &credentials.password,
        ]
        .iter()
        .all(|field| field.is_none())
    }

    pub fn seal_credentials(
        credentials: &CloudCredentials,
        passphrase: &Zeroizing<String>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let encoded = Zeroizing::new(Storage::encode_value(credentials)?);
        let (crypto, kdf) = Crypto::create(passphrase)?;
        let (ciphertext, nonce) = crypto.seal_blob(&encoded)?;
        Ok(Storage::encode_value(&SealedCredentials {
            kdf,
            nonce,
            ciphertext,
        })?)
    }

    pub fn open_credentials(
        sealed_bytes: &[u8],
        passphrase: &Zeroizing<String>,
    ) -> Result<CloudCredentials, Box<dyn std::error::Error>> {
        let sealed = Self::parse_sealed(sealed_bytes)?;
        let plaintext = Self::open_sealed(&sealed, passphrase)?;
        let decoded: CloudCredentials = Storage::decode_value(&plaintext)?;
        Ok(decoded)
    }

    fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Accounts::cortex_dir()?.join(CLOUD_CONFIG_FILE))
    }

    fn store_credentials(
        name: &str,
        credentials: &CloudCredentials,
    ) -> Result<StoredCredentials, Box<dyn std::error::Error>> {
        if Self::holds_no_secret(credentials) {
            Self::delete_keyring_secret(name);
            return Ok((Some(Vec::new()), CredentialStorage::NoSecret));
        }

        let encoded = Zeroizing::new(Storage::encode_value(credentials)?);
        if Self::store_keyring_secret(name, &encoded).is_ok() {
            return Ok((None, CredentialStorage::Keyring));
        }

        let passphrase = prompt_new_cloud_passphrase()?;
        let sealed = Self::seal_credentials(credentials, &passphrase)?;
        Self::delete_keyring_secret(name);
        Ok((Some(sealed), CredentialStorage::Passphrase))
    }

    fn parse_sealed(sealed_bytes: &[u8]) -> Result<SealedCredentials, Box<dyn std::error::Error>> {
        let sealed: SealedCredentials =
            Storage::decode_value(sealed_bytes).map_err(|_| FALLBACK_FORMAT_ERROR)?;
        Ok(sealed)
    }

    fn open_sealed(
        sealed: &SealedCredentials,
        passphrase: &Zeroizing<String>,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
        let crypto = Crypto::open(passphrase, &sealed.kdf).map_err(|_| FALLBACK_FORMAT_ERROR)?;
        let plaintext = crypto
            .open_blob(&sealed.nonce, &sealed.ciphertext)
            .map_err(|_| FALLBACK_DECRYPT_ERROR)?;
        Ok(Zeroizing::new(plaintext))
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

fn prompt_cloud_passphrase() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    UserPrompt::password(CLOUD_PASSPHRASE_PROMPT)
}

fn prompt_new_cloud_passphrase() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let passphrase = UserPrompt::password(NEW_CLOUD_PASSPHRASE_PROMPT)?;
    Password::security_check(&passphrase)?;
    let confirmation = UserPrompt::password(CONFIRM_CLOUD_PASSPHRASE_PROMPT)?;
    Password::match_check(&passphrase, &confirmation)?;
    Ok(passphrase)
}
