use crate::domain::limits::MAX_ENTRIES;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct ExportData {
    pub version: String,
    pub timestamp: u64,
    #[serde(deserialize_with = "ExportData::deserialize_bounded_entries")]
    pub entries: Vec<ExportEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub password: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

impl Drop for ExportEntry {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(description) = self.description.as_mut() {
            description.zeroize();
        }
    }
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

pub struct SecretText;

impl SecretText {
    pub fn decode(bytes: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        match String::from_utf8(bytes) {
            Ok(text) => Ok(text),
            Err(error) => {
                let mut raw = error.into_bytes();
                raw.zeroize();
                Err("Stored secret is not valid UTF-8".into())
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedExport {
    pub version: String,
    pub salt: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl ExportData {
    fn deserialize_bounded_entries<'de, D>(deserializer: D) -> Result<Vec<ExportEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedEntries;

        impl<'de> Visitor<'de> for BoundedEntries {
            type Value = Vec<ExportEntry>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a list of export entries")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some(entry) = sequence.next_element::<ExportEntry>()? {
                    if entries.len() >= MAX_ENTRIES {
                        return Err(de::Error::custom(format!(
                            "Too many entries (limit is {MAX_ENTRIES})"
                        )));
                    }
                    entries.push(entry);
                }
                Ok(entries)
            }
        }

        deserializer.deserialize_seq(BoundedEntries)
    }
}
