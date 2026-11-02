use cortex::core::dump::{DumpFile, decode, encode};

fn sample() -> DumpFile {
    DumpFile {
        salt: vec![2u8; 33],
        nonce: [7u8; 12],
        ciphertext: vec![9u8; 40],
    }
}

#[test]
fn encode_then_decode_round_trips() -> Result<(), String> {
    let bytes = encode(&sample())?;
    let decoded = decode(&bytes)?;
    assert_eq!(decoded.salt, vec![2u8; 33]);
    assert_eq!(decoded.nonce, [7u8; 12]);
    assert_eq!(decoded.ciphertext, vec![9u8; 40]);
    Ok(())
}

#[test]
fn legacy_backup_format_is_rejected_with_clear_message() {
    let error = decode(&[1, 0, 0, 0]).err().unwrap_or_default();
    assert!(error.contains("old backup format"));
}

#[test]
fn previous_dump_format_is_rejected_with_clear_message() {
    let error = decode(&[2, 0, 0, 0]).err().unwrap_or_default();
    assert!(error.contains("older cortex version"));
}

#[test]
fn truncated_and_unknown_files_are_rejected() {
    assert!(decode(&[]).is_err());
    assert!(decode(&[3, 33]).is_err());
    assert!(decode(&[99, 0, 0]).is_err());
    let mut bytes = encode(&sample()).unwrap_or_default();
    bytes.truncate(bytes.len() - 45);
    assert!(decode(&bytes).is_err());
}
