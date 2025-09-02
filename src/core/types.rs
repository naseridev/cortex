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
}

#[derive(Serialize, Deserialize)]
pub struct PasswordEntry {
    pub encrypted_password: Vec<u8>,
    pub encrypted_description: Option<Vec<u8>>,
    pub nonce: [u8; 12],
    pub desc_nonce: Option<[u8; 12]>,
    pub timestamp: u64,
}

pub struct SecureString(String);

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
