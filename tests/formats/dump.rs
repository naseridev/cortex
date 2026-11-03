use cortex::core::dump::{Dump, DumpFile};

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
    let encoded = Dump::encode(&original)?;
    let decoded = Dump::decode(&encoded)?;

    assert_eq!(decoded.salt, original.salt);
    assert_eq!(decoded.nonce, original.nonce);
    assert_eq!(decoded.ciphertext, original.ciphertext);
    Ok(())
}

#[test]
fn encoded_layout_is_version_then_little_endian_salt_length() -> Result<(), String> {
    let bytes = Dump::encode(&sample_dump())?;

    assert_eq!(bytes[0], 3);
    assert_eq!(bytes[1..3], 33u16.to_le_bytes());
    assert_eq!(bytes.len(), 1 + 2 + 33 + 12 + 48);
    Ok(())
}

#[test]
fn legacy_and_previous_dump_versions_report_upgrade_guidance() {
    let v1_err = Dump::decode(&[1, 0, 0, 0])
        .err()
        .expect("legacy dump must be rejected");
    assert!(v1_err.contains("old backup format"));

    let v2_err = Dump::decode(&[2, 0, 0, 0])
        .err()
        .expect("previous dump must be rejected");
    assert!(v2_err.contains("older cortex version"));
}

#[test]
fn unknown_dump_versions_are_reported_as_damaged() {
    for version in [0u8, 4, 255] {
        let error = Dump::decode(&[version, 0, 0, 0])
            .err()
            .expect("unknown version must be rejected");
        assert_eq!(error, "Unsupported or damaged dump file");
    }
}

#[test]
fn truncated_dumps_are_rejected_at_every_structural_boundary() -> Result<(), String> {
    let bytes = Dump::encode(&sample_dump())?;

    for cut in [0, 1, 2, 3, 20, 46, 47, 48] {
        assert!(Dump::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    assert!(Dump::decode(&bytes).is_ok());
    Ok(())
}

#[test]
fn declared_salt_length_must_fit_the_payload() -> Result<(), String> {
    let mut forged = Dump::encode(&sample_dump())?;
    forged[1..3].copy_from_slice(&500u16.to_le_bytes());
    assert!(Dump::decode(&forged).is_err());
    Ok(())
}

#[test]
fn encode_rejects_salts_that_exceed_the_length_field() -> Result<(), String> {
    let oversized = DumpFile {
        salt: vec![0u8; 65_536],
        nonce: [0u8; 12],
        ciphertext: vec![1u8; 4],
    };
    assert!(Dump::encode(&oversized).is_err());

    let largest = DumpFile {
        salt: vec![0u8; 65_535],
        nonce: [0u8; 12],
        ciphertext: vec![1u8; 4],
    };
    let decoded = Dump::decode(&Dump::encode(&largest)?)?;
    assert_eq!(decoded.salt.len(), 65_535);
    Ok(())
}

#[test]
fn empty_ciphertext_is_not_a_valid_dump() {
    let empty = DumpFile {
        salt: vec![2u8; 33],
        nonce: [7u8; 12],
        ciphertext: Vec::new(),
    };
    let bytes = Dump::encode(&empty).expect("encoding does not check ciphertext");
    assert!(Dump::decode(&bytes).is_err());
}

#[test]
fn malformed_dumps_are_rejected() {
    assert!(Dump::decode(&[]).is_err());
    assert!(Dump::decode(&[3, 33]).is_err());
    assert!(Dump::decode(&[99, 0, 0]).is_err());
}
