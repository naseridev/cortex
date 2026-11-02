use cortex::core::crypto::Crypto;
use cortex::core::interchange::{
    CSV_HEADER, FORMAT_VERSION, decode_csv, encode_csv, is_csv, open_encrypted, parse_encrypted,
    validate_import, validate_stored,
};
use cortex::core::limits::MAX_ENTRIES;
use cortex::core::types::{EncryptedExport, ExportEntry};
use zeroize::{Zeroize, Zeroizing};

fn encode_encrypted(
    passphrase: &Zeroizing<String>,
    entries: &[ExportEntry],
    timestamp: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let document = serde_json::json!({
        "version": FORMAT_VERSION,
        "timestamp": timestamp,
        "entries": entries,
    });
    let mut payload = serde_json::to_vec(&document)?;
    let (crypto, salt) = Crypto::create(passphrase)?;
    let sealed = crypto.seal_blob(&payload);
    payload.zeroize();
    let (ciphertext, nonce) = sealed?;
    let file = EncryptedExport {
        version: FORMAT_VERSION.to_string(),
        salt,
        nonce,
        ciphertext,
    };
    Ok(serde_json::to_vec_pretty(&file)?)
}

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
            password: "plain1234".to_string(),
            description: None,
            tags: Vec::new(),
        },
    ]
}

fn assert_same(left: &[ExportEntry], right: &[ExportEntry]) {
    assert_eq!(left.len(), right.len());
    for (a, b) in left.iter().zip(right) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.password, b.password);
        assert_eq!(a.description, b.description);
        assert_eq!(a.tags, b.tags);
    }
}

#[test]
fn csv_round_trip_preserves_every_field() -> Result<(), String> {
    let entries = sample_entries();
    let text = String::from_utf8(encode_csv(&entries)?).map_err(|error| error.to_string())?;
    assert!(is_csv(&text));
    let decoded = decode_csv(&text)?;
    assert_same(&entries, &decoded);
    Ok(())
}

#[test]
fn csv_accepts_bom_and_crlf() -> Result<(), String> {
    let text = format!("\u{feff}{CSV_HEADER}\r\nbank,secret1,,work;finance\r\n");
    let decoded = decode_csv(&text)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].description, None);
    assert_eq!(
        decoded[0].tags,
        vec!["work".to_string(), "finance".to_string()]
    );
    Ok(())
}

#[test]
fn csv_ignores_blank_lines() -> Result<(), String> {
    let text = format!("{CSV_HEADER}\n\nbank,secret1,,\n\n\nmail,secret2,note,work\n\n");
    let decoded = decode_csv(&text)?;
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[1].name, "mail");
    assert_eq!(decoded[1].tags, vec!["work".to_string()]);
    Ok(())
}

#[test]
fn csv_round_trip_keeps_delimiters_quotes_and_newlines() -> Result<(), String> {
    let entries = vec![ExportEntry {
        name: "tricky".to_string(),
        password: "pa,ss\"w\nord ".to_string(),
        description: Some("line one\nline \"two\", end".to_string()),
        tags: vec!["one".to_string(), "two".to_string()],
    }];
    let text = String::from_utf8(encode_csv(&entries)?).map_err(|error| error.to_string())?;
    let decoded = decode_csv(&text)?;
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].password, entries[0].password);
    assert_eq!(decoded[0].description, entries[0].description);
    assert_eq!(decoded[0].tags, entries[0].tags);
    Ok(())
}

#[test]
fn csv_rejects_unknown_header() {
    assert!(decode_csv("name,password\nbank,secret1\n").is_err());
}

#[test]
fn csv_rejects_wrong_field_count() {
    assert!(decode_csv(&format!("{CSV_HEADER}\nbank,secret1,only-three\n")).is_err());
}

#[test]
fn json_text_is_not_csv() {
    assert!(!is_csv("{\n  \"version\": \"4.0.0\"\n}"));
}

#[test]
fn encrypted_round_trip_and_wrong_passphrase() -> Result<(), String> {
    let entries = sample_entries();
    let passphrase = Zeroizing::new("Exp0rt!Passphrase".to_string());
    let bytes = encode_encrypted(&passphrase, &entries, 42).map_err(|error| error.to_string())?;
    let file = parse_encrypted(&bytes)?;
    let data = open_encrypted(&passphrase, &file)?;
    assert_eq!(data.timestamp, 42);
    assert_same(&entries, &data.entries);
    let wrong = Zeroizing::new("Wrong!Passphrase1".to_string());
    assert!(open_encrypted(&wrong, &file).is_err());
    Ok(())
}

#[test]
fn encrypted_rejects_unknown_version() -> Result<(), String> {
    let file = EncryptedExport {
        version: "9.9.9".to_string(),
        salt: Vec::new(),
        nonce: [0u8; 12],
        ciphertext: Vec::new(),
    };
    let bytes = serde_json::to_vec(&file).map_err(|error| error.to_string())?;
    assert!(parse_encrypted(&bytes).is_err());
    Ok(())
}

#[test]
fn plain_json_is_rejected_as_import() {
    assert!(parse_encrypted(b"{\"version\":\"4.0.0\",\"timestamp\":1,\"entries\":[]}").is_err());
}

#[test]
fn validation_rejects_description_containing_password() {
    let mut entry = ExportEntry {
        name: "bank".to_string(),
        password: "plain1234".to_string(),
        description: Some("my plain1234 note".to_string()),
        tags: Vec::new(),
    };
    assert!(validate_stored(&mut entry).is_err());
}

#[test]
fn validation_normalizes_tags_and_empty_description() -> Result<(), String> {
    let mut entry = ExportEntry {
        name: "bank".to_string(),
        password: "plain1234".to_string(),
        description: Some(String::new()),
        tags: vec![
            "Work".to_string(),
            "work".to_string(),
            "Finance".to_string(),
        ],
    };
    validate_stored(&mut entry)?;
    assert_eq!(entry.description, None);
    assert_eq!(entry.tags, vec!["finance".to_string(), "work".to_string()]);
    Ok(())
}

#[test]
fn csv_rejects_more_rows_than_the_entry_limit() {
    let mut text = format!("{CSV_HEADER}\n");
    for _ in 0..=MAX_ENTRIES {
        text.push_str("bank,secret1,,\n");
    }
    assert!(decode_csv(&text).is_err());
}

#[test]
fn import_rejects_control_characters_in_name() {
    let mut entry = ExportEntry {
        name: "bank\u{1b}[2J".to_string(),
        password: "plain1234".to_string(),
        description: None,
        tags: Vec::new(),
    };
    assert!(validate_import(&mut entry).is_err());
}

#[test]
fn import_rejects_control_characters_in_description() {
    let mut entry = ExportEntry {
        name: "bank".to_string(),
        password: "plain1234".to_string(),
        description: Some("first\rsecond".to_string()),
        tags: Vec::new(),
    };
    assert!(validate_import(&mut entry).is_err());
}

#[test]
fn import_enforces_minimum_password_length_but_stored_data_is_not_rejected() {
    let mut entry = ExportEntry {
        name: "legacy".to_string(),
        password: "abc123".to_string(),
        description: None,
        tags: Vec::new(),
    };
    assert!(validate_import(&mut entry).is_err());
    assert!(validate_stored(&mut entry).is_ok());
}
