use cortex::core::crypto::Crypto;
use cortex::core::dump;
use cortex::core::storage::Storage;
use cortex::core::types::PasswordEntry;
use std::fs;
use tempfile::TempDir;

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
fn crud_and_search_operations_maintain_integrity() -> Result<(), Box<dyn std::error::Error>> {
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

    let search_hits = storage.search_entries("alp")?;
    assert_eq!(search_hits.len(), 2);

    assert!(storage.delete_password("beta")?);
    assert!(!storage.delete_password("beta")?);

    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn reserved_names_are_protected_from_user_operations() -> Result<(), Box<dyn std::error::Error>> {
    let (_dir, storage, crypto) = setup_vault()?;
    let dummy = make_entry(&crypto, "__config__", "pass1234")?;

    assert!(storage.create_password("__config__", &dummy).is_err());
    assert!(!storage.edit_password("__config__", &dummy)?);
    assert!(storage.delete_password("__config__").is_err());
    assert!(storage.get_password("__config__")?.is_none());
    Ok(())
}

#[test]
fn integrity_verification_detects_tampering_and_rollback() -> Result<(), Box<dyn std::error::Error>>
{
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;
    let snapshot_raw = storage.get_raw(b"alpha")?.ok_or("missing alpha")?;

    storage.edit_password("alpha", &make_entry(&crypto, "alpha", "second_secret")?)?;
    storage.put_raw(b"alpha", &snapshot_raw)?;
    assert!(storage.verify_integrity().is_err());

    Ok(())
}

#[test]
fn integrity_verification_detects_unauthorized_deletion_and_injection()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, storage, crypto) = setup_vault()?;
    storage.create_password("alpha", &make_entry(&crypto, "alpha", "first_secret")?)?;

    storage.remove_raw(b"alpha")?;
    assert!(storage.verify_integrity().is_err());

    let (_dir2, storage2, crypto2) = setup_vault()?;
    let injected = make_entry(&crypto2, "rogue", "injected_secret")?;
    storage2.put_raw(b"rogue", &postcard::to_allocvec(&injected)?)?;
    assert!(storage2.verify_integrity().is_err());

    Ok(())
}

#[test]
fn atomic_reset_rebuilds_vault_under_new_key() -> Result<(), Box<dyn std::error::Error>> {
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
fn dump_and_restore_preserves_vault_and_rejects_tampered_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let (dump_dir, source, source_crypto) = setup_vault()?;
    source.create_password("one", &make_entry(&source_crypto, "one", "secret_one")?)?;
    source.create_password("two", &make_entry(&source_crypto, "two", "secret_two")?)?;

    let dump_path = source.write_dump(dump_dir.path(), &source_crypto)?;
    let mut dump_file = dump::decode(&fs::read(&dump_path)?)?;

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
