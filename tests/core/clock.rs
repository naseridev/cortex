use cortex::domain::types::PasswordEntry;
use cortex::formats::dump::Dump;
use cortex::security::crypto::Crypto;
use cortex::storage::Storage;
use tempfile::TempDir;

use crate::common::{TestResult, failure};

const FAR_FUTURE: u64 = 4_000_000_000;

fn setup_vault() -> Result<(TempDir, Storage, Crypto), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("vault.redb"))?;
    let crypto = Crypto::from_key([9u8; 32]);
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;
    Ok((dir, storage, crypto))
}

fn entry_at(
    crypto: &Crypto,
    name: &str,
    timestamp: u64,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let mut entry = crypto.create_entry(name, b"secret_value", Some("desc"), None)?;
    entry.timestamp = timestamp;
    Ok(entry)
}

fn stored_timestamp(storage: &Storage, name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let entry = storage.get_password(name)?.ok_or("missing entry")?;
    Ok(entry.timestamp)
}

#[test]
fn write_from_a_slow_clock_is_ordered_after_a_future_timestamp() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &entry_at(&crypto, "alpha", FAR_FUTURE)?)?;
    storage.create_password("beta", &entry_at(&crypto, "beta", 1_000)?)?;

    let alpha = stored_timestamp(&storage, "alpha")?;
    let beta = stored_timestamp(&storage, "beta")?;
    assert_eq!(alpha, FAR_FUTURE);
    assert!(beta > alpha);
    Ok(())
}

#[test]
fn edits_and_deletes_are_stamped_after_existing_timestamps() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &entry_at(&crypto, "alpha", FAR_FUTURE)?)?;
    storage.edit_password("alpha", &entry_at(&crypto, "alpha", 1_000)?)?;
    let edited = stored_timestamp(&storage, "alpha")?;
    assert!(edited > FAR_FUTURE);

    assert!(storage.delete_password("alpha")?);
    let tombstones = storage.list_tombstones()?;
    assert_eq!(tombstones.len(), 1);
    assert!(tombstones[0].1 > edited);
    Ok(())
}

#[test]
fn batch_import_is_stamped_in_order() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    let batch = vec![
        ("alpha".to_string(), entry_at(&crypto, "alpha", FAR_FUTURE)?),
        ("beta".to_string(), entry_at(&crypto, "beta", 1_000)?),
    ];
    storage.put_entries(&batch)?;

    let alpha = stored_timestamp(&storage, "alpha")?;
    let beta = stored_timestamp(&storage, "beta")?;
    assert!(beta > alpha);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn merged_clock_is_kept_for_later_writes() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.atomic_merge(
        &[],
        &[],
        5_000_000_000,
        &crypto,
        &Crypto::encode_salt(&[4u8; 32]),
    )?;

    storage.create_password("alpha", &entry_at(&crypto, "alpha", 1_000)?)?;
    assert!(stored_timestamp(&storage, "alpha")? > 5_000_000_000);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn restored_dump_keeps_the_clock() -> TestResult {
    let (_dir, source, crypto) = setup_vault()?;
    source.create_password("alpha", &entry_at(&crypto, "alpha", FAR_FUTURE)?)?;

    let dump_bytes = source.encode_dump(&crypto)?;
    let dump_file = Dump::decode(&dump_bytes)?;
    let snapshot = Storage::read_dump(&dump_file, &crypto)?;

    let restore_dir = TempDir::new()?;
    let restored = Storage::open_at(&restore_dir.path().join("restored.redb"))?;
    restored.replace_with_dump(&snapshot)?;
    restored.bind_integrity(&crypto);
    restored.verify_integrity()?;

    restored.create_password("beta", &entry_at(&crypto, "beta", 1_000)?)?;
    assert!(stored_timestamp(&restored, "beta")? > FAR_FUTURE);
    Ok(())
}

#[test]
fn clock_record_is_covered_by_the_integrity_manifest() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &entry_at(&crypto, "alpha", FAR_FUTURE)?)?;

    storage.put_raw(b"__clock__", &[0u8])?;
    let error = failure(storage.verify_integrity())?;
    assert!(error.to_string().contains("integrity check failed"));
    Ok(())
}
