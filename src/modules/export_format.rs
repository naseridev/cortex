use crate::{
    core::{
        crypto::Crypto,
        limits::{
            MAX_DESCRIPTION_BYTES, MAX_ENTRIES, MAX_NAME_BYTES, MAX_PASSWORD_BYTES,
            MIN_ACCOUNT_PASSWORD_LENGTH,
        },
        types::{EncryptedExport, ExportData, ExportEntry, SecureString},
    },
    modules::{password::Password, tags::TagValidator},
};
use serde::Serialize;
use zeroize::Zeroize;

pub const FORMAT_VERSION: &str = "4.0.0";
pub const CSV_HEADER: &str = "name,password,description,tags";
const CSV_FIELD_COUNT: usize = 4;
const TAG_SEPARATOR: &str = ";";

#[derive(Serialize)]
struct ExportDocument<'a> {
    version: &'static str,
    timestamp: u64,
    entries: &'a [ExportEntry],
}

pub(crate) fn normalize_and_validate(entry: &mut ExportEntry) -> Result<(), String> {
    if entry.name.trim().is_empty() || entry.name.len() > MAX_NAME_BYTES {
        return Err("Invalid or empty account name".to_string());
    }
    if entry.name.starts_with("__") {
        return Err("Reserved account name".to_string());
    }
    Password::length_check(&entry.password, MIN_ACCOUNT_PASSWORD_LENGTH)
        .map_err(|error| error.to_string())?;
    if entry.password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("Password exceeds {MAX_PASSWORD_BYTES} bytes"));
    }
    if entry.description.as_deref() == Some("") {
        entry.description = None;
    }
    if let Some(description) = &entry.description {
        if description.len() > MAX_DESCRIPTION_BYTES {
            return Err(format!("Description exceeds {MAX_DESCRIPTION_BYTES} bytes"));
        }
        Password::in_desc_check(&entry.password, description).map_err(|error| error.to_string())?;
    }
    entry.tags = TagValidator::normalize(&entry.tags);
    TagValidator::validate(&entry.tags).map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn encode_encrypted(
    passphrase: &SecureString,
    entries: &[ExportEntry],
    timestamp: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let document = ExportDocument {
        version: FORMAT_VERSION,
        timestamp,
        entries,
    };
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

pub(crate) fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedExport, String> {
    let file: EncryptedExport = serde_json::from_slice(bytes).map_err(|error| {
        format!("Unsupported import file, expected an encrypted export or a CSV export: {error}")
    })?;
    if file.version != FORMAT_VERSION {
        return Err(format!("Unsupported export version: {}", file.version));
    }
    Ok(file)
}

pub(crate) fn open_encrypted(
    passphrase: &SecureString,
    file: &EncryptedExport,
) -> Result<ExportData, String> {
    let crypto = Crypto::open(passphrase, &file.salt).map_err(|error| error.to_string())?;
    let mut plaintext = crypto
        .open_blob(&file.nonce, &file.ciphertext)
        .map_err(|_| "Wrong export passphrase or damaged export file".to_string())?;
    let parsed = serde_json::from_slice::<ExportData>(&plaintext)
        .map_err(|error| format!("Invalid export payload: {error}"));
    plaintext.zeroize();
    let data = parsed?;
    if data.version != file.version {
        return Err("Export header and payload versions do not match".to_string());
    }
    Ok(data)
}

pub(crate) fn is_csv(text: &str) -> bool {
    text.strip_prefix('\u{feff}').unwrap_or(text).lines().next() == Some(CSV_HEADER)
}

pub(crate) fn encode_csv(entries: &[ExportEntry]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(CSV_HEADER);
    out.push('\n');
    for entry in entries {
        push_csv_field(&mut out, &entry.name);
        out.push(',');
        push_csv_field(&mut out, &entry.password);
        out.push(',');
        push_csv_field(&mut out, entry.description.as_deref().unwrap_or(""));
        out.push(',');
        push_csv_field(&mut out, &entry.tags.join(TAG_SEPARATOR));
        out.push('\n');
    }
    out.into_bytes()
}

pub(crate) fn decode_csv(text: &str) -> Result<Vec<ExportEntry>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut records = parse_csv_records(text)?.into_iter();
    let header = records.next().ok_or_else(|| "Empty CSV file".to_string())?;
    if header.join(",") != CSV_HEADER {
        return Err("Unrecognized CSV header".to_string());
    }

    let mut entries = Vec::new();
    for (index, fields) in records.enumerate() {
        let row = index + 2;
        let [name, password, description, tags]: [String; CSV_FIELD_COUNT] =
            fields.try_into().map_err(|fields: Vec<String>| {
                format!(
                    "Row {row} has {} fields, expected {CSV_FIELD_COUNT}",
                    fields.len()
                )
            })?;
        entries.push(ExportEntry {
            name,
            password,
            description: if description.is_empty() {
                None
            } else {
                Some(description)
            },
            tags: if tags.is_empty() {
                Vec::new()
            } else {
                tags.split(TAG_SEPARATOR).map(str::to_string).collect()
            },
        });
        if entries.len() > MAX_ENTRIES {
            return Err(format!("Too many entries (limit is {MAX_ENTRIES})"));
        }
    }
    Ok(entries)
}

fn push_csv_field(out: &mut String, field: &str) {
    if field.contains([',', '"', '\n', '\r']) {
        out.push('"');
        for ch in field.chars() {
            if ch == '"' {
                out.push('"');
            }
            out.push(ch);
        }
        out.push('"');
    } else {
        out.push_str(field);
    }
}

fn parse_csv_records(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut after_quote = false;
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch != '"' {
                field.push(ch);
            } else if chars.peek() == Some(&'"') {
                chars.next();
                field.push('"');
            } else {
                in_quotes = false;
                after_quote = true;
            }
            continue;
        }
        match ch {
            '"' if field.is_empty() && !after_quote => in_quotes = true,
            ',' => {
                record.push(std::mem::take(&mut field));
                after_quote = false;
            }
            '\n' => {
                if !(record.is_empty() && field.is_empty() && !after_quote) {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                after_quote = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            _ if after_quote => {
                return Err("Unexpected character after a quoted CSV field".to_string());
            }
            '"' => return Err("Unexpected quote inside a CSV field".to_string()),
            _ => field.push(ch),
        }
    }

    if in_quotes {
        return Err("Unterminated quoted CSV field".to_string());
    }
    if !(record.is_empty() && field.is_empty() && !after_quote) {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let text = String::from_utf8(encode_csv(&entries)).map_err(|error| error.to_string())?;
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
        let passphrase = SecureString::new("Exp0rt!Passphrase".to_string());
        let bytes =
            encode_encrypted(&passphrase, &entries, 42).map_err(|error| error.to_string())?;
        let file = parse_encrypted(&bytes)?;
        let data = open_encrypted(&passphrase, &file)?;
        assert_eq!(data.timestamp, 42);
        assert_same(&entries, &data.entries);
        let wrong = SecureString::new("Wrong!Passphrase1".to_string());
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
        assert!(
            parse_encrypted(b"{\"version\":\"4.0.0\",\"timestamp\":1,\"entries\":[]}").is_err()
        );
    }

    #[test]
    fn validation_rejects_description_containing_password() {
        let mut entry = ExportEntry {
            name: "bank".to_string(),
            password: "plain1234".to_string(),
            description: Some("my plain1234 note".to_string()),
            tags: Vec::new(),
        };
        assert!(normalize_and_validate(&mut entry).is_err());
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
        normalize_and_validate(&mut entry)?;
        assert_eq!(entry.description, None);
        assert_eq!(entry.tags, vec!["finance".to_string(), "work".to_string()]);
        Ok(())
    }
}
