use cortex::core::crypto::Crypto;
use cortex::core::dump;
use cortex::core::storage::{McpPermission, Storage};
use cortex::core::types::PasswordEntry;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn temporary_storage() -> Result<(TempDir, Storage), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let storage = Storage::open_at(&directory.path().join("vault.redb"))?;
    Ok((directory, storage))
}

fn vault_crypto() -> Crypto {
    Crypto::from_key([9u8; 32])
}

fn sealed_entry(
    crypto: &Crypto,
    name: &str,
    password: &str,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    crypto.create_entry(name, password.as_bytes(), None, None)
}

fn initialized_storage() -> Result<(TempDir, Storage, Crypto), Box<dyn std::error::Error>> {
    let (directory, storage) = temporary_storage()?;
    let crypto = vault_crypto();
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;
    Ok((directory, storage, crypto))
}

#[test]
fn account_file_names_are_hashed_and_distinct() {
    let first = Storage::account_file_name("personal");
    let second = Storage::account_file_name("work");
    assert_ne!(first, second);
    assert!(first.ends_with(".redb"));
    assert!(!first.contains("personal"));
}

#[test]
fn mcp_permission_parses_three_digit_binary_flags() -> Result<(), String> {
    let zero = McpPermission::parse("000")?;
    assert!(zero.is_disabled());
    assert!(!zero.can_account());
    assert!(!zero.can_write());
    assert!(!zero.can_read());

    let read_only = McpPermission::parse("001")?;
    assert!(!read_only.is_disabled());
    assert!(!read_only.can_account());
    assert!(!read_only.can_write());
    assert!(read_only.can_read());

    let write_only = McpPermission::parse("010")?;
    assert!(!write_only.can_account());
    assert!(write_only.can_write());
    assert!(!write_only.can_read());

    let account_only = McpPermission::parse("100")?;
    assert!(account_only.can_account());
    assert!(!account_only.can_write());
    assert!(!account_only.can_read());

    let full = McpPermission::parse("111")?;
    assert!(full.can_account());
    assert!(full.can_write());
    assert!(full.can_read());
    assert_eq!(full.as_str(), "111");

    assert!(McpPermission::parse("002").is_err());
    assert!(McpPermission::parse("11").is_err());
    assert!(McpPermission::parse("1111").is_err());
    Ok(())
}

#[test]
fn integrity_holds_across_writes() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, storage, crypto) = initialized_storage()?;
    storage.verify_integrity()?;

    assert!(storage.create_password("alpha", &sealed_entry(&crypto, "alpha", "first-secret")?)?);
    assert!(storage.create_password("beta", &sealed_entry(&crypto, "beta", "second-secret")?)?);
    assert!(storage.edit_password("alpha", &sealed_entry(&crypto, "alpha", "third-secret")?)?);
    assert!(storage.delete_password("beta")?);
    storage.put_entries(&[(
        "gamma".to_string(),
        sealed_entry(&crypto, "gamma", "fourth-secret")?,
    )])?;

    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn integrity_detects_record_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, storage, crypto) = initialized_storage()?;
    storage.create_password("alpha", &sealed_entry(&crypto, "alpha", "first-secret")?)?;
    let original = storage.get_raw(b"alpha")?.ok_or("missing record")?;
    storage.edit_password("alpha", &sealed_entry(&crypto, "alpha", "second-secret")?)?;

    storage.put_raw(b"alpha", &original)?;

    assert!(storage.verify_integrity().is_err());
    Ok(())
}

#[test]
fn integrity_detects_record_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, storage, crypto) = initialized_storage()?;
    storage.create_password("alpha", &sealed_entry(&crypto, "alpha", "first-secret")?)?;

    storage.remove_raw(b"alpha")?;

    assert!(storage.verify_integrity().is_err());
    Ok(())
}

#[test]
fn integrity_detects_injected_record() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, storage, crypto) = initialized_storage()?;
    let injected = sealed_entry(&crypto, "ghost", "injected-secret")?;

    storage.put_raw(
        b"ghost",
        &postcard::to_allocvec(&injected).map_err(|error| error.to_string())?,
    )?;

    assert!(storage.verify_integrity().is_err());
    Ok(())
}

#[test]
fn legacy_vault_without_manifest_is_rejected_until_reset() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, storage, crypto) = initialized_storage()?;
    storage.create_password("alpha", &sealed_entry(&crypto, "alpha", "first-secret")?)?;
    storage.remove_raw(b"__manifest__")?;
    assert!(storage.verify_integrity().is_err());

    let new_crypto = Crypto::from_key([5u8; 32]);
    let rebuilt = vec![(
        "alpha".to_string(),
        sealed_entry(&new_crypto, "alpha", "first-secret")?,
    )];
    storage.atomic_reset(&rebuilt, &new_crypto, &Crypto::encode_salt(&[6u8; 32]))?;

    storage.verify_integrity()?;
    Ok(())
}

#[test]
fn empty_vault_without_manifest_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, storage) = temporary_storage()?;
    storage.bind_integrity(&vault_crypto());
    storage.verify_integrity()?;
    Ok(())
}

fn temporary_dump_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cortex_{name}_{}", std::process::id()))
}

#[test]
fn dump_restores_full_vault_into_another_database() -> Result<(), Box<dyn std::error::Error>> {
    let (_source_directory, source, source_crypto) = initialized_storage()?;
    source.create_password(
        "alpha",
        &sealed_entry(&source_crypto, "alpha", "first-secret")?,
    )?;
    source.create_password(
        "beta",
        &sealed_entry(&source_crypto, "beta", "second-secret")?,
    )?;

    let dir = temporary_dump_dir("dump_restore");
    let path = source.write_dump(&dir, &source_crypto)?;
    let file = dump::decode(&fs::read(&path)?)?;
    let snapshot = Storage::read_dump(&file, &source_crypto)?;
    fs::remove_dir_all(&dir)?;
    assert_eq!(snapshot.user_count(), 2);

    let (_target_directory, target) = temporary_storage()?;
    target.init_db(
        &Crypto::from_key([7u8; 32]),
        &Crypto::encode_salt(&[8u8; 32]),
    )?;
    target.create_password(
        "stale",
        &sealed_entry(&Crypto::from_key([7u8; 32]), "stale", "old-secret")?,
    )?;

    target.replace_with_dump(&snapshot)?;
    target.bind_integrity(&source_crypto);
    target.verify_integrity()?;
    assert!(target.get_password("alpha")?.is_some());
    assert!(target.get_password("beta")?.is_some());
    assert!(target.get_password("stale")?.is_none());
    Ok(())
}

#[test]
fn dump_rejects_wrong_master_password() -> Result<(), Box<dyn std::error::Error>> {
    let (_source_directory, source, source_crypto) = initialized_storage()?;
    source.create_password(
        "alpha",
        &sealed_entry(&source_crypto, "alpha", "first-secret")?,
    )?;

    let dir = temporary_dump_dir("dump_wrong_password");
    let path = source.write_dump(&dir, &source_crypto)?;
    let file = dump::decode(&fs::read(&path)?)?;
    fs::remove_dir_all(&dir)?;

    assert!(Storage::read_dump(&file, &Crypto::from_key([6u8; 32])).is_err());
    Ok(())
}

#[test]
fn dump_rejects_salt_header_that_does_not_match_contents() -> Result<(), Box<dyn std::error::Error>>
{
    let (_source_directory, source, source_crypto) = initialized_storage()?;
    source.create_password(
        "alpha",
        &sealed_entry(&source_crypto, "alpha", "first-secret")?,
    )?;

    let dir = temporary_dump_dir("dump_header_mismatch");
    let path = source.write_dump(&dir, &source_crypto)?;
    let mut file = dump::decode(&fs::read(&path)?)?;
    fs::remove_dir_all(&dir)?;
    file.salt = Crypto::encode_salt(&[1u8; 32]);

    assert!(Storage::read_dump(&file, &source_crypto).is_err());
    Ok(())
}
