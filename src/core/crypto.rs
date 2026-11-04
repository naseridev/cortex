use crate::core::time::Time;
use crate::core::types::{PasswordEntry, SecretText};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead, aead::Payload};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const KDF_VERSION_ARGON2: u8 = 4;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_TIME: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

const FIELD_PASSWORD: &str = "password";
const FIELD_DESCRIPTION: &str = "description";
const FIELD_TAGS: &str = "tags";
const BLOB_NAME: &str = "cortex_export";
const BLOB_FIELD: &str = "payload";
const DUMP_NAME: &str = "cortex_dump";
const DUMP_FIELD: &str = "snapshot";
const INTEGRITY_CONTEXT: &str = "cortex vault integrity key v1";

type OptionalSealed = (Option<Vec<u8>>, Option<[u8; NONCE_LENGTH]>);

pub struct Crypto {
    key: [u8; KEY_LENGTH],
}

impl Drop for Crypto {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Crypto {
    pub fn create(
        master_password: &Zeroizing<String>,
    ) -> Result<(Self, Vec<u8>), Box<dyn std::error::Error>> {
        let salt = Self::generate_salt()?;
        let crypto = Self::from_argon2(master_password.as_bytes(), &salt)?;

        Ok((crypto, Self::encode_salt(&salt)))
    }

    pub fn open(
        master_password: &Zeroizing<String>,
        salt_blob: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match salt_blob {
            [KDF_VERSION_ARGON2, salt @ ..] if salt.len() == SALT_LENGTH => {
                let mut salt_array = [0u8; SALT_LENGTH];
                salt_array.copy_from_slice(salt);

                Self::from_argon2(master_password.as_bytes(), &salt_array)
            }
            _ => Err("Unrecognized key derivation format".into()),
        }
    }

    #[must_use]
    pub fn from_key(key: [u8; KEY_LENGTH]) -> Self {
        Self::from_parts(key)
    }

    #[must_use]
    pub fn key(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    #[must_use]
    pub fn verification(&self) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(self.key.as_slice());
        hasher.finalize().as_bytes().to_vec()
    }

    #[must_use]
    pub fn integrity_key(&self) -> [u8; KEY_LENGTH] {
        blake3::derive_key(INTEGRITY_CONTEXT, &self.key)
    }

    #[must_use]
    pub fn matches_verification(&self, verification_data: &[u8]) -> bool {
        let computed = self.verification();
        bool::from(computed.as_slice().ct_eq(verification_data))
    }

    pub fn create_entry(
        &self,
        name: &str,
        data: &[u8],
        description: Option<&str>,
        tags: Option<&[String]>,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let (encrypted_password, nonce) = self.seal(name, FIELD_PASSWORD, data)?;
        let (encrypted_description, desc_nonce) =
            self.seal_optional(name, FIELD_DESCRIPTION, description.map(str::as_bytes))?;

        let tags_json = match tags.filter(|list| !list.is_empty()) {
            Some(list) => Some(Zeroizing::new(
                serde_json::to_string(list)
                    .map_err(|error| format!("Tag serialization failed: {error}"))?,
            )),
            None => None,
        };

        let (encrypted_tags, tags_nonce) =
            self.seal_optional(name, FIELD_TAGS, tags_json.as_ref().map(|s| s.as_bytes()))?;

        Ok(PasswordEntry {
            encrypted_password,
            encrypted_description,
            encrypted_tags,
            nonce,
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
        let (Some(ciphertext), Some(nonce)) = (&entry.encrypted_description, &entry.desc_nonce)
        else {
            return Ok(None);
        };

        let plaintext = self
            .open_field(name, FIELD_DESCRIPTION, nonce, ciphertext)
            .map_err(|error| format!("Description decryption failed: {error:?}"))?;
        Ok(Some(SecretText::decode(plaintext)?))
    }

    pub fn decrypt_tags(
        &self,
        name: &str,
        entry: &PasswordEntry,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let (Some(ciphertext), Some(nonce)) = (&entry.encrypted_tags, &entry.tags_nonce) else {
            return Ok(Vec::new());
        };

        let plaintext = Zeroizing::new(
            self.open_field(name, FIELD_TAGS, nonce, ciphertext)
                .map_err(|error| format!("Tags decryption failed: {error:?}"))?,
        );
        let tags: Vec<String> = serde_json::from_slice(&plaintext)
            .map_err(|error| format!("Tag deserialization failed: {error}"))?;

        Ok(tags)
    }

    pub fn generate_salt() -> Result<[u8; SALT_LENGTH], Box<dyn std::error::Error>> {
        let mut salt = [0u8; SALT_LENGTH];
        getrandom::fill(&mut salt)
            .map_err(|error| format!("Failed to read OS randomness: {error}"))?;

        Ok(salt)
    }

    #[must_use]
    pub fn encode_salt(salt: &[u8; SALT_LENGTH]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(salt.len() + 1);
        blob.push(KDF_VERSION_ARGON2);
        blob.extend_from_slice(salt);
        blob
    }

    fn from_argon2(
        password: &[u8],
        salt: &[u8; SALT_LENGTH],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME,
            ARGON2_PARALLELISM,
            Some(KEY_LENGTH),
        )
        .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; KEY_LENGTH];
        if let Err(error) = argon.hash_password_into(password, salt, &mut key) {
            key.zeroize();
            return Err(format!("Argon2id derivation failed: {error}").into());
        }

        Ok(Self::from_parts(key))
    }

    fn from_parts(key: [u8; KEY_LENGTH]) -> Self {
        Self { key }
    }

    pub fn seal_blob(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LENGTH]), Box<dyn std::error::Error>> {
        self.seal(BLOB_NAME, BLOB_FIELD, plaintext)
    }

    pub fn open_blob(
        &self,
        nonce: &[u8; NONCE_LENGTH],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.open_field(BLOB_NAME, BLOB_FIELD, nonce, ciphertext)
            .map_err(|error| format!("Blob decryption failed: {error:?}").into())
    }

    pub fn seal_dump(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LENGTH]), Box<dyn std::error::Error>> {
        self.seal(DUMP_NAME, DUMP_FIELD, plaintext)
    }

    pub fn open_dump(
        &self,
        nonce: &[u8; NONCE_LENGTH],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.open_field(DUMP_NAME, DUMP_FIELD, nonce, ciphertext)
            .map_err(|error| format!("Dump decryption failed: {error:?}").into())
    }

    fn seal(
        &self,
        name: &str,
        field: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LENGTH]), Box<dyn std::error::Error>> {
        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|error| format!("Failed to read OS randomness: {error}"))?;

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = Nonce::from(nonce_bytes);
        let aad = Self::associated_data(name, field);
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|error| format!("{field} encryption failed: {error:?}"))?;

        Ok((encrypted, nonce_bytes))
    }

    fn seal_optional(
        &self,
        name: &str,
        field: &str,
        plaintext: Option<&[u8]>,
    ) -> Result<OptionalSealed, Box<dyn std::error::Error>> {
        match plaintext {
            Some(bytes) => {
                let (ciphertext, nonce) = self.seal(name, field, bytes)?;
                Ok((Some(ciphertext), Some(nonce)))
            }
            None => Ok((None, None)),
        }
    }

    fn open_field(
        &self,
        name: &str,
        field: &str,
        nonce_bytes: &[u8; NONCE_LENGTH],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce = Nonce::from(*nonce_bytes);
        let aad = Self::associated_data(name, field);

        cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
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
}
