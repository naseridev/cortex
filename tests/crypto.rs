use cortex::core::crypto::Crypto;
use zeroize::Zeroizing;

#[test]
fn argon2_create_and_open_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let password = Zeroizing::new("Str0ng!MasterPass".to_string());
    let wrong = Zeroizing::new("Wr0ng!MasterPass".to_string());

    let (created, salt) = Crypto::create(&password)?;
    let opened = Crypto::open(&password, &salt)?;
    let wrong_opened = Crypto::open(&wrong, &salt)?;

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
fn entry_encryption_binds_associated_data_to_entry_name() -> Result<(), Box<dyn std::error::Error>>
{
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
fn entry_without_optional_fields_decrypts_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = Crypto::from_key([2u8; 32]);
    let entry = crypto.create_entry("minimal", b"password123", None, None)?;

    assert_eq!(crypto.decrypt_entry("minimal", &entry)?, b"password123");
    assert_eq!(crypto.decrypt_description("minimal", &entry)?, None);
    assert_eq!(crypto.decrypt_tags("minimal", &entry)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn dump_and_blob_sealing_reject_wrong_keys() -> Result<(), Box<dyn std::error::Error>> {
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
fn integrity_key_and_verification_digest_are_domain_separated() {
    let crypto = Crypto::from_key([5u8; 32]);
    assert_ne!(
        crypto.integrity_key().as_slice(),
        crypto.verification().as_slice()
    );
    assert_ne!(crypto.integrity_key().as_slice(), crypto.key().as_slice());
}
