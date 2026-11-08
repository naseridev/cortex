use crate::support::setup_vault;
use cortex::domain::types::PasswordEntry;
use cortex::formats::dump::Dump;
use cortex::security::crypto::Crypto;
use cortex::storage::Storage;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use crate::common::{TestResult, failure};

fn make_entry(
    crypto: &Crypto,
    name: &str,
    password: &str,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    crypto.create_entry(name, password.as_bytes(), Some("desc"), None)
}

fn integrity_error(storage: &Storage) -> Result<String, Box<dyn std::error::Error>> {
    Ok(failure(storage.verify_integrity())?.to_string())
}

#[test]
fn crud_operations_maintain_integrity() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;

    assert!(storage.create_password("alpha", &make_entry(&crypto, "alpha", "pass1234")?)?);
    assert!(!storage.create_password("alpha", &make_entry(&crypto, "alpha", "duplicate")?)?);
    assert!(storage.create_password("beta", &make_entry(&crypto, "beta", "pass5678")?)?);

    let listed = storage.list_entries()?;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].0, "alpha");
    assert_eq!(listed[1].0, "beta");

    assert!(storage.edit_password("alpha", &make_entry(&crypto, "alpha", "updated123")?)?);
    assert!(!storage.edit_password("missing", &make_entry(&crypto, "missing", "pass1234")?)?);

    let raw_hits = storage.search_entries("alp")?;
    let names: Vec<&str> = raw_hits.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"]);

    assert!(storage.delete_password("beta")?);
    assert!(!storage.delete_password("beta")?);

    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn search_returns_candidates_without_reserved_records() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    assert!(storage.search_entries("anything")?.is_empty());

    storage.create_password("alpha", &make_entry(&crypto, "alpha", "pass1234")?)?;
    let candidates = storage.search_entries("zzz")?;
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, "alpha");
    Ok(())
}

#[test]
fn search_rejects_empty_and_oversized_patterns() -> TestResult {
    let (_dir, storage, _crypto) = setup_vault()?;
    assert!(storage.search_entries("   ").is_err());
    assert!(storage.search_entries(&"a".repeat(101)).is_err());
    assert!(storage.search_entries(&"a".repeat(100)).is_ok());
    Ok(())
}

#[test]
fn listing_and_lookup_exclude_reserved_records() -> TestResult {
    let (_dir, storage, _crypto) = setup_vault()?;

    assert!(storage.list_entries()?.is_empty());
    assert!(storage.get_all_entries()?.is_empty());
    assert!(!storage.entry_exists("__init__")?);
    assert!(!storage.entry_exists("__salt__")?);
    assert!(storage.get_password("__manifest__")?.is_none());
    Ok(())
}

#[test]
fn reserved_names_are_protected_from_user_operations() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    let dummy = make_entry(&crypto, "__config__", "pass1234")?;

    assert!(storage.create_password("__config__", &dummy).is_err());
    assert!(!storage.edit_password("__config__", &dummy)?);
    assert!(storage.delete_password("__config__").is_err());
    assert!(storage.get_password("__config__")?.is_none());
    assert!(!storage.entry_exists("__config__")?);
    Ok(())
}

#[test]
fn empty_names_are_rejected_on_create_and_delete() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    let entry = make_entry(&crypto, "", "pass1234")?;

    assert!(storage.create_password("", &entry).is_err());
    assert!(storage.delete_password("").is_err());
    Ok(())
}

#[test]
fn put_entries_is_all_or_nothing_when_a_name_is_reserved() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    let batch = vec![
        (
            "alpha".to_string(),
            make_entry(&crypto, "alpha", "pass1234")?,
        ),
        (
            "__config__".to_string(),
            make_entry(&crypto, "__config__", "pass1234")?,
        ),
    ];

    assert!(storage.put_entries(&batch).is_err());
    assert!(storage.get_password("alpha")?.is_none());
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn put_entries_writes_a_batch_and_accepts_an_empty_one() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.put_entries(&[])?;

    let batch = vec![
        (
            "alpha".to_string(),
            make_entry(&crypto, "alpha", "pass1234")?,
        ),
        ("beta".to_string(), make_entry(&crypto, "beta", "pass5678")?),
    ];
    storage.put_entries(&batch)?;

    assert_eq!(storage.list_entries()?.len(), 2);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn integrity_verification_detects_tampering_and_rollback() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    let snapshot_raw = storage.get_raw(b"alpha")?.ok_or("missing alpha")?;

    storage.edit_password("alpha", &make_entry(&crypto, "alpha", "second_secret")?)?;
    storage.put_raw(b"alpha", &snapshot_raw)?;
    assert!(integrity_error(&storage)?.contains("integrity check failed"));
    Ok(())
}

#[test]
fn integrity_verification_detects_unauthorized_deletion_and_injection() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;

    storage.remove_raw(b"alpha")?;
    assert!(integrity_error(&storage)?.contains("integrity check failed"));

    let (_dir2, storage2, crypto2) = setup_vault()?;
    let injected = make_entry(&crypto2, "rogue", "injected_secret")?;
    storage2.put_raw(b"rogue", &postcard::to_allocvec(&injected)?)?;
    assert!(integrity_error(&storage2)?.contains("integrity check failed"));
    Ok(())
}

#[test]
fn tampered_manifest_record_is_detected() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "pass1234")?)?;

    storage.put_raw(b"__manifest__", &[0u8; 5])?;
    assert!(integrity_error(&storage)?.contains("integrity check failed"));
    Ok(())
}

#[test]
fn reserved_bookkeeping_records_do_not_affect_integrity() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "pass1234")?)?;

    storage.put_raw(b"__throttle__", &3u32.to_le_bytes())?;
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn fresh_vault_without_user_records_verifies() -> TestResult {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("empty.redb"))?;
    storage.bind_integrity(&Crypto::from_key([1u8; 32]));
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn legacy_vault_without_manifest_requires_an_upgrade() -> TestResult {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("legacy.redb"))?;
    storage.bind_integrity(&Crypto::from_key([1u8; 32]));
    storage.put_raw(b"alpha", b"opaque-record")?;

    assert!(integrity_error(&storage)?.contains("predates integrity protection"));
    Ok(())
}

#[test]
fn writes_are_refused_until_the_storage_is_bound_to_a_key() -> TestResult {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("unbound.redb"))?;
    let crypto = Crypto::from_key([3u8; 32]);
    let entry = make_entry(&crypto, "alpha", "pass1234")?;

    assert!(storage.create_password("alpha", &entry).is_err());
    Ok(())
}

#[test]
fn atomic_reset_rebuilds_vault_under_new_key() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "secret123")?)?;

    let new_crypto = Crypto::from_key([11u8; 32]);
    let new_entries = vec![(
        "alpha".to_string(),
        make_entry(&new_crypto, "alpha", "secret123")?,
    )];
    storage.atomic_reset(&new_entries, &new_crypto, &Crypto::encode_salt(&[12u8; 32]))?;

    storage.verify_integrity()?;
    let stored = storage.get_password("alpha")?.ok_or("missing alpha")?;
    assert_eq!(new_crypto.decrypt_entry("alpha", &stored)?, b"secret123");
    Ok(())
}

#[test]
fn atomic_reset_drops_entries_absent_from_the_new_set() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "secret123")?)?;
    storage.create_password("beta", &make_entry(&crypto, "beta", "secret456")?)?;

    let new_crypto = Crypto::from_key([11u8; 32]);
    let kept = vec![(
        "alpha".to_string(),
        make_entry(&new_crypto, "alpha", "secret123")?,
    )];
    storage.atomic_reset(&kept, &new_crypto, &Crypto::encode_salt(&[12u8; 32]))?;

    assert!(storage.get_password("beta")?.is_none());
    assert_eq!(storage.list_entries()?.len(), 1);
    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn salt_and_verification_metadata_are_recorded_at_init() -> TestResult {
    let (_dir, storage, crypto) = setup_vault()?;
    assert_eq!(storage.get_salt()?, Some(Crypto::encode_salt(&[4u8; 32])));
    assert_eq!(
        storage.get_verification_data()?,
        Some(crypto.verification())
    );
    Ok(())
}

#[test]
fn second_open_of_a_locked_database_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("vault.redb");
    let _first = Storage::open_at(&path)?;

    let error = Storage::open_at(&path)
        .err()
        .ok_or("second open should fail")?;
    assert_eq!(error.to_string(), "Database is locked by another process");
    Ok(())
}

#[test]
fn dump_and_restore_preserves_vault_and_rejects_tampered_headers() -> TestResult {
    let (dump_dir, source, source_crypto) = setup_vault()?;
    source.create_password("one", &make_entry(&source_crypto, "one", "secret_one")?)?;
    source.create_password("two", &make_entry(&source_crypto, "two", "secret_two")?)?;

    let dump_path = source.write_dump(dump_dir.path(), &source_crypto)?;
    let mut dump_file = Dump::decode(&fs::read(&dump_path)?)?;

    let snapshot = Storage::read_dump(&dump_file, &source_crypto)?;
    assert_eq!(snapshot.user_count(), 2);

    assert!(Storage::read_dump(&dump_file, &Crypto::from_key([99u8; 32])).is_err());

    let (_target_dir, target, _) = setup_vault()?;
    target.replace_with_dump(&snapshot)?;
    target.bind_integrity(&source_crypto);
    target.verify_integrity()?;
    assert!(target.get_password("one")?.is_some());
    assert!(target.get_password("two")?.is_some());

    dump_file.salt = Crypto::encode_salt(&[0u8; 32]);
    assert!(Storage::read_dump(&dump_file, &source_crypto).is_err());
    Ok(())
}

#[test]
fn dump_file_name_follows_the_dump_pattern() -> TestResult {
    let (dump_dir, storage, crypto) = setup_vault()?;
    let path = storage.write_dump(dump_dir.path(), &crypto)?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("no file name")?;
    assert!(file_name.starts_with("dump_"));
    assert!(
        Path::new(file_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
    );
    assert_eq!(file_name.len(), "dump_".len() + 20 + ".bin".len());
    Ok(())
}

#[cfg(unix)]
#[test]
fn dump_files_are_owner_only() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let (dump_dir, storage, crypto) = setup_vault()?;
    let path = storage.write_dump(dump_dir.path(), &crypto)?;
    let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    Ok(())
}

#[test]
fn tampered_dump_ciphertext_is_rejected() -> TestResult {
    let (dump_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "pass1234")?)?;
    let path = storage.write_dump(dump_dir.path(), &crypto)?;

    let mut bytes = fs::read(&path)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let dump_file = Dump::decode(&bytes)?;

    assert!(Storage::read_dump(&dump_file, &crypto).is_err());
    Ok(())
}

#[test]
fn empty_vault_dump_round_trips_with_zero_user_entries() -> TestResult {
    let (dump_dir, storage, crypto) = setup_vault()?;
    let path = storage.write_dump(dump_dir.path(), &crypto)?;

    let dump_file = Dump::decode(&fs::read(&path)?)?;
    let snapshot = Storage::read_dump(&dump_file, &crypto)?;
    assert_eq!(snapshot.user_count(), 0);
    Ok(())
}

#[test]
fn restore_replaces_existing_contents() -> TestResult {
    let (dump_dir, source, source_crypto) = setup_vault()?;
    source.create_password("one", &make_entry(&source_crypto, "one", "secret_one")?)?;
    let path = source.write_dump(dump_dir.path(), &source_crypto)?;
    let snapshot = Storage::read_dump(&Dump::decode(&fs::read(&path)?)?, &source_crypto)?;

    let (_target_dir, target, target_crypto) = setup_vault()?;
    target.create_password("old", &make_entry(&target_crypto, "old", "old_secret")?)?;

    target.replace_with_dump(&snapshot)?;
    target.bind_integrity(&source_crypto);
    assert!(target.get_password("old")?.is_none());
    assert!(target.get_password("one")?.is_some());
    target.verify_integrity()?;
    Ok(())
}

#[test]
fn restore_discards_the_failed_attempt_counter() -> TestResult {
    let (dump_dir, source, source_crypto) = setup_vault()?;
    source.create_password("one", &make_entry(&source_crypto, "one", "secret_one")?)?;
    source.put_raw(b"__throttle__", &9u32.to_le_bytes())?;
    let path = source.write_dump(dump_dir.path(), &source_crypto)?;
    let snapshot = Storage::read_dump(&Dump::decode(&fs::read(&path)?)?, &source_crypto)?;

    let (_target_dir, target, _) = setup_vault()?;
    target.replace_with_dump(&snapshot)?;
    assert!(target.get_raw(b"__throttle__")?.is_none());
    Ok(())
}
