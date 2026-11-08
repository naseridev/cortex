use cortex::commands::account::reset::{PlainEntry, decrypt_all, reencrypt_all};
use cortex::security::crypto::Crypto;

use crate::common::TestResult;

#[test]
fn reencryption_keeps_name_password_description_and_tags() -> TestResult {
    let old_crypto = Crypto::from_key([7u8; 32]);
    let new_crypto = Crypto::from_key([8u8; 32]);
    let tags = vec!["mail".to_string(), "work".to_string()];
    let stored = vec![(
        "alpha".to_string(),
        old_crypto.create_entry("alpha", b"secret123", Some("desc"), Some(tags.as_slice()))?,
    )];

    let plain: Vec<PlainEntry> = decrypt_all(&stored, &old_crypto)?;
    let reencrypted = reencrypt_all(&plain, &new_crypto)?;
    let restored = decrypt_all(&reencrypted, &new_crypto)?;

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].name, "alpha");
    assert_eq!(restored[0].password.as_str(), "secret123");
    assert_eq!(restored[0].description.as_deref(), Some("desc"));
    assert_eq!(restored[0].tags, tags);
    Ok(())
}
