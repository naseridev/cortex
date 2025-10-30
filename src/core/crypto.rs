use crate::core::time::Time;
use crate::core::types::{PasswordEntry, SecureString};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};
use sysinfo::{CpuExt, System, SystemExt};

const TEST_DATA: &[u8] = b"cortex_test_data";
const HARDWARE_SALT: &[u8] = b"cortex_hardware_salt_v1";

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(master_password: &SecureString) -> Self {
        let cipher = ChaCha20Poly1305::new(&Self::derive_key(master_password.as_bytes()));
        Self { cipher }
    }

    pub fn create_entry(
        &self,
        data: &[u8],
        description: Option<&str>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| "Encryption failed")?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let mut desc_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut desc_nonce_bytes);
            let desc_nonce = Nonce::from_slice(&desc_nonce_bytes);

            let encrypted_desc = self
                .cipher
                .encrypt(desc_nonce, desc.as_bytes())
                .map_err(|_| "Description encryption failed")?;

            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        Ok(PasswordEntry {
            encrypted_password: encrypted,
            encrypted_description,
            nonce: nonce_bytes,
            desc_nonce,
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
            .map_err(|_| "Decryption failed".into())
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
                .map_err(|_| "Description decryption failed")?;

            Ok(Some(String::from_utf8(decrypted)?))
        } else {
            Ok(None)
        }
    }

    pub fn verify_test_data(&self, entry: &PasswordEntry) -> bool {
        self.decrypt_entry(entry)
            .map(|d| d == TEST_DATA)
            .unwrap_or(false)
    }

    pub fn encrypt_with_new_key(
        new_password: &SecureString,
        data: &[u8],
        description: Option<&str>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let new_cipher = ChaCha20Poly1305::new(&Self::derive_key(new_password.as_bytes()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = new_cipher
            .encrypt(nonce, data)
            .map_err(|_| "Encryption failed")?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let mut desc_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut desc_nonce_bytes);
            let desc_nonce = Nonce::from_slice(&desc_nonce_bytes);

            let encrypted_desc = new_cipher
                .encrypt(desc_nonce, desc.as_bytes())
                .map_err(|_| "Description encryption failed")?;

            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        Ok(PasswordEntry {
            encrypted_password: encrypted,
            encrypted_description,
            nonce: nonce_bytes,
            desc_nonce,
            timestamp: Time::current_timestamp(),
        })
    }

    fn derive_key(password: &[u8]) -> Key {
        let hardware_id = Self::get_hardware_id();
        let mut hasher = Hasher::new();

        hasher.update(password);
        hasher.update(&hardware_id);

        let hash = hasher.finalize();
        let key_bytes: [u8; 32] = hash.as_bytes()[..32]
            .try_into()
            .expect("Hash size mismatch");
        Key::from(key_bytes)
    }

    fn get_hardware_id() -> Vec<u8> {
        let mut hasher = Hasher::new();
        let mut sys = System::new_all();
        sys.refresh_cpu();

        if let Some(cpu) = sys.cpus().first() {
            let brand = cpu.brand();
            if !brand.is_empty() {
                hasher.update(brand.as_bytes());
            }
        }

        hasher.update(HARDWARE_SALT);
        hasher.finalize().as_bytes().to_vec()
    }
}

pub fn get_test_data() -> &'static [u8] {
    TEST_DATA
}
