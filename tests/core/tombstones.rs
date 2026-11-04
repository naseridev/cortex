use cortex::core::crypto::Crypto;
use cortex::core::dump::Dump;
use cortex::core::storage::Storage;
use cortex::core::types::PasswordEntry;
use tempfile::TempDir;

use crate::common::{TestResult, failure};

const ALPHA_TOMBSTONE: &[u8] = b"__tombstone__/alpha";

fn setup_vault() -> Result<(TempDir, Storage, Crypto), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("vault.redb"))?;
    let crypto = Crypto::from_key([9u8; 32]);
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;
    Ok((dir, storage, crypto))
}

fn make_entry(
    crypto: &Crypto,
    name: &str,
    password: &str,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    crypto.create_entry(name, password.as_bytes(), Some("desc"), None)
}

#[test]
fn deleting_an_entry_leaves_a_tombstone_until_it_is_recreated() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;

    assert!(storage.delete_password("alpha")?);
    assert_eq!(storage.list_entries()?.len(), 0);
    let tombstones = storage.list_tombstones()?;
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].0, "alpha");
    storage.verify_integrity()?;

    assert!(storage.create_password("alpha", &make_entry(&crypto, "alpha", "second_secret")?)?);
    assert_eq!(storage.list_tombstones()?, Vec::new());
    assert_eq!(storage.list_entries()?.len(), 1);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn tombstones_are_covered_by_the_integrity_manifest() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    storage.delete_password("alpha")?;

    storage.remove_raw(ALPHA_TOMBSTONE)?;
    let error = failure(storage.verify_integrity())?;
    assert!(error.to_string().contains("integrity check failed"));
    Ok(())
}

#[test]
fn tombstones_survive_a_dump_and_restore() -> TestResult {
    let (_dir, source, crypto) = setup_vault()?;
    source.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    source.delete_password("alpha")?;
    let expected = source.list_tombstones()?;

    let dump_bytes = source.encode_dump(&crypto)?;
    let dump_file = Dump::decode(&dump_bytes)?;
    let snapshot = Storage::read_dump(&dump_file, &crypto)?;

    let restore_dir = TempDir::new()?;
    let restored = Storage::open_at(&restore_dir.path().join("restored.redb"))?;
    restored.replace_with_dump(&snapshot)?;
    restored.bind_integrity(&crypto);
    restored.verify_integrity()?;

    assert_eq!(restored.list_tombstones()?, expected);
    assert_eq!(restored.list_entries()?.len(), 0);
    Ok(())
}

#[test]
fn master_password_reset_keeps_tombstones() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    storage.delete_password("alpha")?;
    let expected = storage.list_tombstones()?;

    let new_crypto = Crypto::from_key([5u8; 32]);
    storage.atomic_reset(&[], &new_crypto, &Crypto::encode_salt(&[6u8; 32]))?;

    assert_eq!(storage.list_tombstones()?, expected);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn atomic_merge_replaces_the_tombstone_set() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    storage.delete_password("alpha")?;

    let merged = vec![("beta".to_string(), 5u64)];
    storage.atomic_merge(&[], &merged, &crypto, &Crypto::encode_salt(&[4u8; 32]))?;

    assert_eq!(storage.list_tombstones()?, merged);
    assert_eq!(storage.list_entries()?.len(), 0);
    storage.verify_integrity()?;
    Ok(())
}
