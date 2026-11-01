use crate::core::time::Time;
use crate::core::types::{PasswordEntry, SecureString, decode_secret_text};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead, aead::Payload};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

const KDF_VERSION_ARGON2: u8 = 4;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

const FIELD_PASSWORD: &str = "password";
const FIELD_DESCRIPTION: &str = "description";
const FIELD_TAGS: &str = "tags";
const BLOB_NAME: &str = "cortex_export";
const BLOB_FIELD: &str = "payload";

pub struct Crypto {
    cipher: ChaCha20Poly1305,
    key: [u8; 32],
}

impl Drop for Crypto {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Crypto {
    pub fn create(
        master_password: &SecureString,
    ) -> Result<(Self, Vec<u8>), Box<dyn std::error::Error>> {
        let salt = Self::generate_salt();
        let crypto = Self::from_argon2(master_password.as_bytes(), &salt)?;
        Ok((crypto, Self::encode_salt(&salt)))
    }

    pub fn open(
        master_password: &SecureString,
        salt_blob: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match salt_blob {
            [KDF_VERSION_ARGON2, salt @ ..] if salt.len() == 32 => {
                let mut salt_array = [0u8; 32];
                salt_array.copy_from_slice(salt);
                Self::from_argon2(master_password.as_bytes(), &salt_array)
            }
            _ => Err("Unrecognized key derivation format".into()),
        }
    }

    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self::from_parts(key)
    }

    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[must_use]
    pub fn verification(&self) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(self.key.as_slice());
        hasher.finalize().as_bytes().to_vec()
    }

    #[must_use]
    pub fn matches_verification(&self, verification_data: &[u8]) -> bool {
        let computed = self.verification();
        if computed.len() != verification_data.len() {
            return false;
        }
        let mut diff = 0u8;
        for (left, right) in computed.iter().zip(verification_data.iter()) {
            diff |= left ^ right;
        }
        diff == 0
    }

    pub fn create_entry(
        &self,
        name: &str,
        data: &[u8],
        description: Option<&str>,
        tags: Option<&[String]>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let (encrypted, nonce_bytes) = self.seal(name, FIELD_PASSWORD, data)?;

        let (encrypted_description, desc_nonce) = if let Some(desc) = description {
            let (encrypted_desc, desc_nonce_bytes) =
                self.seal(name, FIELD_DESCRIPTION, desc.as_bytes())?;
            (Some(encrypted_desc), Some(desc_nonce_bytes))
        } else {
            (None, None)
        };

        let (encrypted_tags, tags_nonce) = if let Some(tag_list) = tags {
            if tag_list.is_empty() {
                (None, None)
            } else {
                let tags_json = serde_json::to_string(tag_list)
                    .map_err(|error| format!("Tag serialization failed: {error}"))?;
                let (encrypted_tags, tags_nonce_bytes) =
                    self.seal(name, FIELD_TAGS, tags_json.as_bytes())?;
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
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.open_field(
            name,
            FIELD_PASSWORD,
            &entry.nonce,
            &entry.encrypted_password,
        )
        .map_err(|error| format!("Decryption failed: {error:?}").into())
    }

    pub fn decrypt_description(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        if let (Some(encrypted_desc), Some(desc_nonce)) =
            (&entry.encrypted_description, &entry.desc_nonce)
        {
            let decrypted = self
                .open_field(name, FIELD_DESCRIPTION, desc_nonce, encrypted_desc)
                .map_err(|error| format!("Description decryption failed: {error:?}"))?;
            Ok(Some(decode_secret_text(decrypted)?))
        } else {
            Ok(None)
        }
    }

    pub fn decrypt_tags(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if let (Some(encrypted_tags), Some(tags_nonce)) = (&entry.encrypted_tags, &entry.tags_nonce)
        {
            let decrypted = self
                .open_field(name, FIELD_TAGS, tags_nonce, encrypted_tags)
                .map_err(|error| format!("Tags decryption failed: {error:?}"))?;
            let tags: Vec<String> = serde_json::from_slice(&decrypted)
                .map_err(|error| format!("Tag deserialization failed: {error}"))?;
            Ok(tags)
        } else {
            Ok(Vec::new())
        }
    }

    #[must_use]
    pub fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    #[must_use]
    pub fn encode_salt(salt: &[u8; 32]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(salt.len() + 1);
        blob.push(KDF_VERSION_ARGON2);
        blob.extend_from_slice(salt);
        blob
    }

    fn from_argon2(password: &[u8], salt: &[u8; 32]) -> Result<Self, Box<dyn std::error::Error>> {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_PARALLELISM, Some(32))
            .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        if let Err(error) = argon.hash_password_into(password, salt, &mut key) {
            key.zeroize();
            return Err(format!("Argon2id derivation failed: {error}").into());
        }
        Ok(Self::from_parts(key))
    }

    fn from_parts(key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new((&key).into());
        Self { cipher, key }
    }

    pub fn seal_blob(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), Box<dyn std::error::Error>> {
        self.seal(BLOB_NAME, BLOB_FIELD, plaintext)
    }

    pub fn open_blob(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.open_field(BLOB_NAME, BLOB_FIELD, nonce, ciphertext)
            .map_err(|error| format!("Blob decryption failed: {error:?}").into())
    }

    fn seal(
        &self,
        name: &str,
        field: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = associated_data(name, field);
        let encrypted = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|error| format!("{field} encryption failed: {error:?}"))?;
        Ok((encrypted, nonce_bytes))
    }

    fn open_field(
        &self,
        name: &str,
        field: &str,
        nonce_bytes: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let nonce = Nonce::from_slice(nonce_bytes);
        let aad = associated_data(name, field);
        self.cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
    }
}

fn associated_data(name: &str, field: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let field_bytes = field.as_bytes();
    let name_len = u32::try_from(name_bytes.len()).unwrap_or(u32::MAX);
    let mut data = Vec::with_capacity(4 + name_bytes.len() + field_bytes.len());
    data.extend_from_slice(&name_len.to_le_bytes());
    data.extend_from_slice(name_bytes);
    data.extend_from_slice(field_bytes);
    data
}
