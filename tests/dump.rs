use cortex::core::dump::{DumpFile, decode, encode};

fn sample_dump() -> DumpFile {
    DumpFile {
        salt: vec![2u8; 33],
        nonce: [7u8; 12],
        ciphertext: vec![9u8; 48],
    }
}

#[test]
fn binary_dump_format_round_trips() -> Result<(), String> {
    let original = sample_dump();
    let encoded = encode(&original)?;
    let decoded = decode(&encoded)?;

    assert_eq!(decoded.salt, original.salt);
    assert_eq!(decoded.nonce, original.nonce);
    assert_eq!(decoded.ciphertext, original.ciphertext);
    Ok(())
}

#[test]
fn legacy_and_previous_dump_versions_report_upgrade_guidance() {
    let v1_err = decode(&[1, 0, 0, 0]).err().unwrap_or_default();
    assert!(v1_err.contains("old backup format"));

    let v2_err = decode(&[2, 0, 0, 0]).err().unwrap_or_default();
    assert!(v2_err.contains("older cortex version"));
}

#[test]
fn malformed_or_truncated_dumps_are_rejected() {
    assert!(decode(&[]).is_err());
    assert!(decode(&[3, 33]).is_err());
    assert!(decode(&[99, 0, 0]).is_err());

    let mut bytes = encode(&sample_dump()).unwrap_or_default();
    bytes.truncate(bytes.len() - 48);
    assert!(decode(&bytes).is_err());
}
