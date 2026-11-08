use cortex::domain::limits::MAX_ENTRIES;
use cortex::domain::types::{EncryptedExport, ExportData, ExportEntry};
use cortex::formats::interchange::{CSV_HEADER, FORMAT_VERSION, Interchange};
use cortex::security::crypto::Crypto;
use zeroize::{Zeroize, Zeroizing};

use crate::common::{TestResult, failure};

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

fn export_entry(
    name: &str,
    password: &str,
    description: Option<&str>,
    tags: &[&str],
) -> ExportEntry {
    ExportEntry {
        name: name.to_string(),
        password: password.to_string(),
        description: description.map(str::to_string),
        tags: tags.iter().map(ToString::to_string).collect(),
    }
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
fn csv_serialization_preserves_multiline_and_special_delimiters() -> TestResult {
    let entries = sample_entries();
    let csv_text = String::from_utf8(Interchange::encode_csv(&entries)?)?;
    assert!(Interchange::is_csv(&csv_text));

    let decoded = Interchange::decode_csv(&csv_text)?;
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
fn csv_output_starts_with_the_canonical_header() -> TestResult {
    let text = String::from_utf8(Interchange::encode_csv(&sample_entries())?)?;
    assert_eq!(text.lines().next(), Some(CSV_HEADER));
    Ok(())
}

#[test]
fn csv_handles_utf8_bom_crlf_and_blank_lines() -> TestResult {
    let raw = format!("\u{feff}{CSV_HEADER}\r\n\r\nbank,secret123,,work;ops\r\n\r\n");
    assert!(Interchange::is_csv(&raw));

    let decoded = Interchange::decode_csv(&raw)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, "bank");
    assert_eq!(decoded[0].description, None);
    assert_eq!(decoded[0].tags, vec!["work".to_string(), "ops".to_string()]);
    Ok(())
}

#[test]
fn csv_rejects_invalid_headers_and_column_counts() {
    assert!(Interchange::decode_csv("wrong,header\na,b\n").is_err());
    assert!(Interchange::decode_csv(&format!("{CSV_HEADER}\nonly_one_column\n")).is_err());
    assert!(!Interchange::is_csv("{\"version\":\"4.0.0\"}"));
}

#[test]
fn csv_rejects_rows_with_too_many_fields() -> TestResult {
    let text = format!("{CSV_HEADER}\nname,secret123,,tags,extra\n");
    let error = failure(Interchange::decode_csv(&text))?;
    assert!(error.contains("has 5 fields"));
    Ok(())
}

#[test]
fn csv_header_detection_is_exact() {
    assert!(!Interchange::is_csv("NAME,PASSWORD,DESCRIPTION,TAGS"));
    assert!(!Interchange::is_csv(""));
}

#[test]
fn csv_without_data_rows_decodes_to_no_entries() -> TestResult {
    let text = format!("{CSV_HEADER}\n");
    assert!(Interchange::decode_csv(&text)?.is_empty());
    Ok(())
}

#[test]
fn csv_rejects_empty_input_and_byte_order_mark_only() {
    assert_eq!(
        Interchange::decode_csv("").err().as_deref(),
        Some("Empty CSV file")
    );
    assert!(Interchange::decode_csv("\u{feff}").is_err());
}

#[test]
fn csv_enforces_maximum_entry_limit() {
    let mut csv_text = format!("{CSV_HEADER}\n");
    for _ in 0..=MAX_ENTRIES {
        csv_text.push_str("item,password123,,\n");
    }
    assert!(Interchange::decode_csv(&csv_text).is_err());
}

#[test]
fn csv_accepts_exactly_the_maximum_entry_count() -> TestResult {
    let mut csv_text = format!("{CSV_HEADER}\n");
    for _ in 0..MAX_ENTRIES {
        csv_text.push_str("item,password123,,\n");
    }
    assert_eq!(Interchange::decode_csv(&csv_text)?.len(), MAX_ENTRIES);
    Ok(())
}

#[test]
fn encrypted_export_round_trips_and_verifies_passphrase() -> TestResult {
    let entries = sample_entries();
    let pass = Zeroizing::new("Export#Pass123".to_string());
    let wrong = Zeroizing::new("Wrong#Pass123".to_string());

    let bytes = build_encrypted_export(&pass, &entries, 100)?;
    let parsed = Interchange::parse_encrypted(&bytes)?;
    let data = Interchange::open_encrypted(&pass, &parsed)?;

    assert_eq!(data.version, FORMAT_VERSION);
    assert_eq!(data.timestamp, 100);
    assert_eq!(data.entries.len(), 2);
    assert!(Interchange::open_encrypted(&wrong, &parsed).is_err());
    Ok(())
}

#[test]
fn encrypted_export_with_tampered_ciphertext_is_rejected() -> TestResult {
    let pass = Zeroizing::new("Export#Pass123".to_string());
    let bytes = build_encrypted_export(&pass, &sample_entries(), 100)?;
    let mut parsed = Interchange::parse_encrypted(&bytes)?;
    parsed.ciphertext[0] ^= 0x01;

    let error = failure(Interchange::open_encrypted(&pass, &parsed))?;
    assert_eq!(error, "Wrong export passphrase or damaged export file");
    Ok(())
}

#[test]
fn encrypted_export_rejects_payload_version_mismatch() -> TestResult {
    let pass = Zeroizing::new("Export#Pass123".to_string());
    let (crypto, salt) = Crypto::create(&pass)?;
    let payload = serde_json::to_vec(&ExportData {
        version: "3.0.0".to_string(),
        timestamp: 1,
        entries: sample_entries(),
    })?;
    let (ciphertext, nonce) = crypto.seal_blob(&payload)?;
    let file = EncryptedExport {
        version: FORMAT_VERSION.to_string(),
        salt,
        nonce,
        ciphertext,
    };

    let error = failure(Interchange::open_encrypted(&pass, &file))?;
    assert_eq!(error, "Export header and payload versions do not match");
    Ok(())
}

#[test]
fn parse_encrypted_rejects_non_json_and_unknown_versions() -> TestResult {
    let not_json = Interchange::parse_encrypted(b"plain text");
    assert!(
        not_json
            .err()
            .is_some_and(|e| e.starts_with("Unsupported import file"))
    );

    let file = EncryptedExport {
        version: "3.0.0".to_string(),
        salt: vec![4u8; 33],
        nonce: [0u8; 12],
        ciphertext: vec![1u8; 16],
    };
    let bytes = serde_json::to_vec(&file)?;
    let error = failure(Interchange::parse_encrypted(&bytes))?;
    assert_eq!(error, "Unsupported export version: 3.0.0");
    Ok(())
}

#[test]
fn open_encrypted_rejects_unrecognized_salt_before_deriving_a_key() {
    let pass = Zeroizing::new("Export#Pass123".to_string());
    let file = EncryptedExport {
        version: FORMAT_VERSION.to_string(),
        salt: vec![9u8; 4],
        nonce: [0u8; 12],
        ciphertext: vec![1u8; 16],
    };
    assert!(Interchange::open_encrypted(&pass, &file).is_err());
}

#[test]
fn import_validation_rejects_short_passwords_and_reserved_names() {
    let mut short_pass = export_entry("legacy", "short", None, &[]);
    assert!(Interchange::would_fail_import(&short_pass));
    assert!(Interchange::validate_import(&mut short_pass).is_err());

    let mut reserved = export_entry("__system", "valid_password_123", None, &[]);
    assert!(Interchange::would_fail_import(&reserved));
    assert!(Interchange::validate_import(&mut reserved).is_err());
}

#[test]
fn import_validation_rejects_overlong_names() {
    let mut overlong = export_entry(&"x".repeat(129), "valid_password_123", None, &[]);
    assert!(Interchange::validate_import(&mut overlong).is_err());
}

#[test]
fn import_validation_rejects_control_characters_in_descriptions() {
    let entry = export_entry("bank", "valid_password_123", Some("line\nbreak"), &[]);
    assert!(Interchange::would_fail_import(&entry));
}

#[test]
fn import_validation_normalizes_a_valid_entry() -> TestResult {
    let mut valid = export_entry("github", "valid_password_123", Some(""), &["Dev", "dev"]);
    assert!(!Interchange::would_fail_import(&valid));
    Interchange::validate_import(&mut valid)?;

    assert_eq!(valid.description, None);
    assert_eq!(valid.tags, vec!["dev".to_string()]);
    Ok(())
}

#[test]
fn stored_validation_accepts_legacy_short_passwords() -> TestResult {
    let mut legacy = export_entry("legacy", "short", None, &[]);
    Interchange::validate_stored(&mut legacy)?;
    Ok(())
}

#[test]
fn stored_validation_rejects_descriptions_that_leak_the_password() {
    let mut leaked = export_entry("leaked", "supersecret", Some("my supersecret note"), &[]);
    assert!(Interchange::validate_stored(&mut leaked).is_err());
}

#[test]
fn stored_validation_rejects_passwords_longer_than_the_byte_limit() -> TestResult {
    let mut long = export_entry("long", &"p".repeat(129), None, &[]);
    let error = failure(Interchange::validate_stored(&mut long))?;
    assert_eq!(error, "Password exceeds 128 bytes");
    Ok(())
}

#[test]
fn stored_validation_rejects_descriptions_over_the_byte_limit() -> TestResult {
    let mut long = export_entry("long", "pass1234", Some(&"d".repeat(501)), &[]);
    let error = failure(Interchange::validate_stored(&mut long))?;
    assert_eq!(error, "Description exceeds 500 bytes");
    Ok(())
}

#[test]
fn stored_validation_rejects_reserved_and_empty_names() {
    let mut reserved = export_entry("__config__", "pass1234", None, &[]);
    assert!(Interchange::validate_stored(&mut reserved).is_err());

    let mut blank = export_entry("   ", "pass1234", None, &[]);
    assert!(Interchange::validate_stored(&mut blank).is_err());
}

#[test]
fn stored_validation_normalizes_and_rejects_invalid_tags() -> TestResult {
    let mut tagged = export_entry("bank", "pass1234", None, &["B", "a", "b"]);
    Interchange::validate_stored(&mut tagged)?;
    assert_eq!(tagged.tags, vec!["a".to_string(), "b".to_string()]);

    let mut invalid = export_entry("bank", "pass1234", None, &["bad tag"]);
    assert!(Interchange::validate_stored(&mut invalid).is_err());
    Ok(())
}
