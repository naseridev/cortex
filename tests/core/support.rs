use cortex::{security::crypto::Crypto, storage::Storage};
use tempfile::TempDir;

pub fn setup_vault() -> Result<(TempDir, Storage, Crypto), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("vault.redb"))?;
    let crypto = Crypto::from_key([9u8; 32]);
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;
    Ok((dir, storage, crypto))
}
