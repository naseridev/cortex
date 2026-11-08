use cortex::domain::types::PasswordEntry;
use cortex::security::crypto::Crypto;
use zeroize::Zeroizing;

use crate::common::TestResult;

#[test]
fn argon2_create_and_open_round_trips() -> TestResult {
    let password = Zeroizing::new("Str0ng!MasterPass".to_string());
    let wrong = Zeroizing::new("Wr0ng!MasterPass".to_string());

    let (created, salt) = Crypto::create(&password)?;
    let opened = Crypto::open(&password, &salt)?;
    let wrong_opened = Crypto::open(&wrong, &salt)?;

    assert_eq!(salt.len(), 33);
    assert_eq!(opened.key(), created.key());
    assert!(opened.matches_verification(&created.verification()));
    assert!(!wrong_opened.matches_verification(&created.verification()));
    Ok(())
}

#[test]
fn open_rejects_invalid_salt_format() {
    let password = Zeroizing::new("Str0ng!MasterPass".to_string());
    assert!(Crypto::open(&password, &[]).is_err());
    assert!(Crypto::open(&password, &[4, 1, 2, 3]).is_err());
    assert!(Crypto::open(&password, &[99; 33]).is_err());
}

#[test]
fn generated_salts_are_fresh_and_encoded_with_a_version_prefix() -> TestResult {
    let first = Crypto::generate_salt()?;
    let second = Crypto::generate_salt()?;
    assert_ne!(first, second);

    let encoded = Crypto::encode_salt(&first);
    assert_eq!(encoded.len(), 33);
    assert_eq!(&encoded[1..], &first[..]);
    Ok(())
}

#[test]
fn entry_encryption_binds_associated_data_to_entry_name() -> TestResult {
    let crypto = Crypto::from_key([7u8; 32]);
    let tags = vec!["finance".to_string(), "urgent".to_string()];
    let entry = crypto.create_entry("bank", b"s3cr3t_pass", Some("main account"), Some(&tags))?;

    assert_eq!(crypto.decrypt_entry("bank", &entry)?, b"s3cr3t_pass");
    assert_eq!(
        crypto.decrypt_description("bank", &entry)?,
        Some("main account".to_string())
    );
    assert_eq!(crypto.decrypt_tags("bank", &entry)?, tags);

    assert!(crypto.decrypt_entry("other_name", &entry).is_err());
    assert!(crypto.decrypt_description("other_name", &entry).is_err());
    assert!(crypto.decrypt_tags("other_name", &entry).is_err());
    Ok(())
}

#[test]
fn entry_without_optional_fields_decrypts_cleanly() -> TestResult {
    let crypto = Crypto::from_key([2u8; 32]);
    let entry = crypto.create_entry("minimal", b"password123", None, None)?;

    assert_eq!(crypto.decrypt_entry("minimal", &entry)?, b"password123");
    assert_eq!(crypto.decrypt_description("minimal", &entry)?, None);
    assert_eq!(
        crypto.decrypt_tags("minimal", &entry)?,
        Vec::<String>::new()
    );
    assert!(entry.encrypted_description.is_none());
    assert!(entry.desc_nonce.is_none());
    assert!(entry.encrypted_tags.is_none());
    assert!(entry.tags_nonce.is_none());
    Ok(())
}

#[test]
fn empty_tag_list_is_stored_as_absent_tags() -> TestResult {
    let crypto = Crypto::from_key([2u8; 32]);
    let none: &[String] = &[];
    let entry = crypto.create_entry("bare", b"password123", None, Some(none))?;

    assert!(entry.encrypted_tags.is_none());
    assert!(entry.tags_nonce.is_none());
    assert_eq!(crypto.decrypt_tags("bare", &entry)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn identical_plaintexts_produce_distinct_ciphertexts() -> TestResult {
    let crypto = Crypto::from_key([2u8; 32]);
    let first = crypto.create_entry("bank", b"same-secret", None, None)?;
    let second = crypto.create_entry("bank", b"same-secret", None, None)?;

    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.encrypted_password, second.encrypted_password);
    Ok(())
}

#[test]
fn entries_cannot_be_decrypted_with_a_different_key() -> TestResult {
    let crypto = Crypto::from_key([2u8; 32]);
    let other = Crypto::from_key([3u8; 32]);
    let entry = crypto.create_entry("bank", b"password123", Some("note"), None)?;

    assert!(other.decrypt_entry("bank", &entry).is_err());
    assert!(other.decrypt_description("bank", &entry).is_err());
    Ok(())
}

#[test]
fn tampered_ciphertext_is_rejected() -> TestResult {
    let crypto = Crypto::from_key([2u8; 32]);
    let entry = crypto.create_entry("bank", b"password123", None, None)?;

    let mut tampered: PasswordEntry = entry.clone();
    tampered.encrypted_password[0] ^= 0x01;
    assert!(crypto.decrypt_entry("bank", &tampered).is_err());
    Ok(())
}

#[test]
fn description_ciphertext_cannot_be_replayed_as_password_field() -> TestResult {
    let crypto = Crypto::from_key([6u8; 32]);
    let entry = crypto.create_entry("bank", b"s3cr3t_pass", Some("main account"), None)?;

    let forged = PasswordEntry {
        encrypted_description: Some(entry.encrypted_password.clone()),
        desc_nonce: Some(entry.nonce),
        ..entry.clone()
    };
    assert!(crypto.decrypt_description("bank", &forged).is_err());
    Ok(())
}

#[test]
fn dump_and_blob_sealing_reject_wrong_keys() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let other = Crypto::from_key([4u8; 32]);

    let (dump_cipher, dump_nonce) = crypto.seal_dump(b"snapshot payload")?;
    assert_eq!(
        crypto.open_dump(&dump_nonce, &dump_cipher)?,
        b"snapshot payload"
    );
    assert!(other.open_dump(&dump_nonce, &dump_cipher).is_err());

    let (blob_cipher, blob_nonce) = crypto.seal_blob(b"export payload")?;
    assert_eq!(
        crypto.open_blob(&blob_nonce, &blob_cipher)?,
        b"export payload"
    );
    assert!(other.open_blob(&blob_nonce, &blob_cipher).is_err());
    Ok(())
}

#[test]
fn sealed_payloads_are_domain_separated() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);

    let (blob_cipher, blob_nonce) = crypto.seal_blob(b"export payload")?;
    assert!(crypto.open_dump(&blob_nonce, &blob_cipher).is_err());

    let (dump_cipher, dump_nonce) = crypto.seal_dump(b"snapshot payload")?;
    assert!(crypto.open_blob(&dump_nonce, &dump_cipher).is_err());
    Ok(())
}

#[test]
fn integrity_key_and_verification_digest_are_domain_separated() {
    let crypto = Crypto::from_key([5u8; 32]);
    assert_ne!(
        crypto.integrity_key().as_slice(),
        crypto.verification().as_slice()
    );
    assert_ne!(crypto.integrity_key().as_slice(), crypto.key().as_slice());
}

#[test]
fn verification_digest_is_stable_and_rejects_truncated_input() {
    let crypto = Crypto::from_key([5u8; 32]);
    let verification = crypto.verification();

    assert_eq!(verification.len(), 32);
    assert_eq!(verification, crypto.verification());
    assert!(crypto.matches_verification(&verification));
    assert!(!crypto.matches_verification(&verification[..31]));
}
