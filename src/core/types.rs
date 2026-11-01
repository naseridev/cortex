use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct ExportData {
    pub version: String,
    pub timestamp: u64,
    pub entries: Vec<ExportEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub password: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub encrypted_password: Vec<u8>,
    pub encrypted_description: Option<Vec<u8>>,
    pub encrypted_tags: Option<Vec<u8>>,
    pub nonce: [u8; 12],
    pub desc_nonce: Option<[u8; 12]>,
    pub tags_nonce: Option<[u8; 12]>,
    pub timestamp: u64,
}

pub struct SecureString(String);

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecureString {
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(s)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub fn decode_secret_text(bytes: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => {
            let mut raw = error.into_bytes();
            raw.zeroize();
            Err("Stored secret is not valid UTF-8".into())
        }
    }
}