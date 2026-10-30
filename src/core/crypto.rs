use crate::core::time::Time;
use crate::core::types::{PasswordEntry, SecureString};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};
use std::sync::OnceLock;
use sysinfo::{CpuRefreshKind, RefreshKind, System};
use zeroize::Zeroize;

const KDF_ITERATIONS: u32 = 600_000;

static HARDWARE_ID_CACHE: OnceLock<Vec<u8>> = OnceLock::new();

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(master_password: &SecureString, salt: &[u8]) -> Self {
        let mut key = Self::derive_key(master_password.as_bytes(), salt);
        let cipher = ChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();
        Self { cipher }
    }

    pub fn create_entry(
        &self,
        data: &[u8],
        description: Option<&str>,
        tags: Option<&[String]>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let mut desc_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut desc_nonce_bytes);
            let desc_nonce = Nonce::from_slice(&desc_nonce_bytes);

            let encrypted_desc = self
                .cipher
                .encrypt(desc_nonce, desc.as_bytes())
                .map_err(|e| format!("Description encryption failed: {:?}", e))?;

            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        let (encrypted_tags, tags_nonce) = if let Some(tag_list) = tags {
            if tag_list.is_empty() {
                (None, None)
            } else {
                let tags_json = serde_json::to_string(tag_list)
                    .map_err(|e| format!("Tag serialization failed: {}", e))?;
                let mut tags_nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut tags_nonce_bytes);
                let tags_nonce = Nonce::from_slice(&tags_nonce_bytes);

                let encrypted_tags = self
                    .cipher
                    .encrypt(tags_nonce, tags_json.as_bytes())
                    .map_err(|e| format!("Tags encryption failed: {:?}", e))?;

                (Some(encrypted_tags), Some(tags_nonce_bytes))
            }
        } else {
            (None, None)
        };

        Ok(PasswordEntry {
            encrypted_password: encrypted,
            encrypted_description,
            encrypted_tags,
            nonce: nonce_bytes,
            desc_nonce,
            tags_nonce,
            timestamp: Time::current_timestamp(),
        })
    }

    pub fn decrypt_entry(
        &self,
        entry: &PasswordEntry,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let nonce = Nonce::from_slice(&entry.nonce);
        self.cipher
            .decrypt(nonce, entry.encrypted_password.as_ref())
            .map_err(|e| format!("Decryption failed: {:?}", e).into())
    }

    pub fn decrypt_description(
        &self,
        entry: &PasswordEntry,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        if let (Some(encrypted_desc), Some(desc_nonce)) =
            (&entry.encrypted_description, &entry.desc_nonce)
        {
            let nonce = Nonce::from_slice(desc_nonce);
            let decrypted = self
                .cipher
                .decrypt(nonce, encrypted_desc.as_ref())
                .map_err(|e| format!("Description decryption failed: {:?}", e))?;

            Ok(Some(String::from_utf8(decrypted).map_err(|e| {
                format!("Invalid UTF-8 in description: {}", e)
            })?))
        } else {
            Ok(None)
        }
    }

    pub fn decrypt_tags(
        &self,
        entry: &PasswordEntry,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if let (Some(encrypted_tags), Some(tags_nonce)) = (&entry.encrypted_tags, &entry.tags_nonce)
        {
            let nonce = Nonce::from_slice(tags_nonce);
            let decrypted = self
                .cipher
                .decrypt(nonce, encrypted_tags.as_ref())
                .map_err(|e| format!("Tags decryption failed: {:?}", e))?;

            let tags: Vec<String> = serde_json::from_slice(&decrypted)
                .map_err(|e| format!("Tag deserialization failed: {}", e))?;
            Ok(tags)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn verify_password(
        master_password: &SecureString,
        salt: &[u8],
        verification_data: &[u8],
    ) -> bool {
        let mut derived_key = Self::derive_key(master_password.as_bytes(), salt);
        let mut hasher = Hasher::new();
        hasher.update(derived_key.as_slice());
        derived_key.as_mut_slice().zeroize();
        let computed_hash = hasher.finalize();

        let a = computed_hash.as_bytes();
        if a.len() != verification_data.len() {
            return false;
        }

        let mut diff = 0u8;
        for (x, y) in a.iter().zip(verification_data.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    pub fn create_verification_data(master_password: &SecureString, salt: &[u8]) -> Vec<u8> {
        let mut derived_key = Self::derive_key(master_password.as_bytes(), salt);
        let mut hasher = Hasher::new();
        hasher.update(derived_key.as_slice());
        derived_key.as_mut_slice().zeroize();
        hasher.finalize().as_bytes().to_vec()
    }

    fn derive_key(password: &[u8], salt: &[u8]) -> Key {
        let hardware_id = Self::get_hardware_id();

        let mut hasher = Hasher::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(hardware_id);

        let mut derived = *hasher.finalize().as_bytes();

        for _ in 0..KDF_ITERATIONS {
            let mut hasher = Hasher::new();
            hasher.update(&derived);
            hasher.update(salt);
            hasher.update(hardware_id);
            derived = *hasher.finalize().as_bytes();
        }

        let key = Key::from(derived);
        derived.zeroize();
        key
    }

    pub fn get_hardware_id() -> &'static [u8] {
        HARDWARE_ID_CACHE.get_or_init(|| {
            let mut hasher = Hasher::new();
            let sys =
                System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::new()));

            if let Some(cpu) = sys.cpus().first() {
                let brand = cpu.brand();
                if !brand.is_empty() {
                    hasher.update(brand.as_bytes());
                }
            }

            hasher.update(b"cortex_hardware_binding");
            hasher.finalize().as_bytes().to_vec()
        })
    }

    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }
}
