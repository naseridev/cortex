use cortex::core::crypto::Crypto;
use cortex::core::interchange::{
    CSV_HEADER, FORMAT_VERSION, decode_csv, encode_csv, is_csv, open_encrypted, parse_encrypted,
    validate_import, validate_stored, would_fail_import,
};
use cortex::core::limits::MAX_ENTRIES;
use cortex::core::types::{EncryptedExport, ExportEntry};
use zeroize::{Zeroize, Zeroizing};

fn sample_entries() -> Vec<ExportEntry> {
    vec![
        ExportEntry {
            name: "bank".to_string(),
            password: " pa,ss\"w0rd\n x ".to_string(),
            description: Some("main, \"login\"".to_string()),
            tags: vec!["finance".to_string(), "work".to_string()],
        },
        ExportEntry {
            name: "mail".to_string(),
            password: "plain12345".to_string(),
            description: None,
            tags: Vec::new(),
        },
    ]
}

fn build_encrypted_export(
    passphrase: &Zeroizing<String>,
    entries: &[ExportEntry],
    timestamp: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let payload_json = serde_json::json!({
        "version": FORMAT_VERSION,
        "timestamp": timestamp,
        "entries": entries,
    });
    let mut raw = serde_json::to_vec(&payload_json)?;
    let (crypto, salt) = Crypto::create(passphrase)?;
    let (ciphertext, nonce) = crypto.seal_blob(&raw)?;
    raw.zeroize();

    let export = EncryptedExport {
        version: FORMAT_VERSION.to_string(),
        salt,
        nonce,
        ciphertext,
    };
    Ok(serde_json::to_vec_pretty(&export)?)
}

#[test]
fn csv_serialization_preserves_multiline_and_special_delimiters() -> Result<(), String> {
    let entries = sample_entries();
    let csv_text = String::from_utf8(encode_csv(&entries)?).map_err(|e| e.to_string())?;
    assert!(is_csv(&csv_text));

    let decoded = decode_csv(&csv_text)?;
    assert_eq!(decoded.len(), entries.len());
    for (left, right) in entries.iter().zip(decoded.iter()) {
        assert_eq!(left.name, right.name);
        assert_eq!(left.password, right.password);
        assert_eq!(left.description, right.description);
        assert_eq!(left.tags, right.tags);
    }
    Ok(())
}

#[test]
fn csv_handles_utf8_bom_crlf_and_blank_lines() -> Result<(), String> {
    let raw = format!("\u{feff}{CSV_HEADER}\r\n\r\nbank,secret123,,work;ops\r\n\r\n");
    assert!(is_csv(&raw));

    let decoded = decode_csv(&raw)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, "bank");
    assert_eq!(decoded[0].description, None);
    assert_eq!(decoded[0].tags, vec!["work".to_string(), "ops".to_string()]);
    Ok(())
}

#[test]
fn csv_rejects_invalid_headers_and_column_counts() {
    assert!(decode_csv("wrong,header\na,b\n").is_err());
    assert!(decode_csv(&format!("{CSV_HEADER}\nonly_one_column\n")).is_err());
    assert!(!is_csv("{\"version\":\"4.0.0\"}"));
}

#[test]
fn csv_enforces_maximum_entry_limit() {
    let mut csv_text = format!("{CSV_HEADER}\n");
    for _ in 0..=MAX_ENTRIES {
        csv_text.push_str("item,password123,,\n");
    }
    assert!(decode_csv(&csv_text).is_err());
}

#[test]
fn encrypted_export_round_trips_and_verifies_passphrase() -> Result<(), String> {
    let entries = sample_entries();
    let pass = Zeroizing::new("Export#Pass123".to_string());
    let wrong = Zeroizing::new("Wrong#Pass123".to_string());

    let bytes = build_encrypted_export(&pass, &entries, 100).map_err(|e| e.to_string())?;
    let parsed = parse_encrypted(&bytes)?;
    let data = open_encrypted(&pass, &parsed)?;

    assert_eq!(data.timestamp, 100);
    assert_eq!(data.entries.len(), 2);
    assert!(open_encrypted(&wrong, &parsed).is_err());
    Ok(())
}

#[test]
fn import_and_stored_validators_enforce_security_constraints() -> Result<(), String> {
    let mut valid = ExportEntry {
        name: "github".to_string(),
        password: "valid_password_123".to_string(),
        description: Some(String::new()),
        tags: vec!["Dev".to_string(), "dev".to_string()],
    };
    assert!(!would_fail_import(&valid));
    validate_import(&mut valid)?;
    assert_eq!(valid.description, None);
    assert_eq!(valid.tags, vec!["dev".to_string()]);

    let mut short_pass = ExportEntry {
        name: "legacy".to_string(),
        password: "short".to_string(),
        description: None,
        tags: Vec::new(),
    };
    assert!(would_fail_import(&short_pass));
    assert!(validate_import(&mut short_pass).is_err());
    assert!(validate_stored(&mut short_pass).is_ok());

    let mut leaked_pass = ExportEntry {
        name: "leaked".to_string(),
        password: "supersecret".to_string(),
        description: Some("my supersecret note".to_string()),
        tags: Vec::new(),
    };
    assert!(validate_stored(&mut leaked_pass).is_err());

    Ok(())
}