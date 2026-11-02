use cortex::core::crypto::Crypto;

#[test]
fn dump_round_trip_and_wrong_key_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = Crypto::from_key([3u8; 32]);
    let other = Crypto::from_key([4u8; 32]);
    let (ciphertext, nonce) = crypto.seal_dump(b"snapshot bytes")?;

    assert_eq!(
        crypto.open_dump(&nonce, &ciphertext)?,
        b"snapshot bytes".to_vec()
    );
    assert!(other.open_dump(&nonce, &ciphertext).is_err());
    Ok(())
}

#[test]
fn integrity_key_differs_from_verification_value() {
    let crypto = Crypto::from_key([5u8; 32]);
    assert_ne!(
        crypto.integrity_key().as_slice(),
        crypto.verification().as_slice()
    );
}
