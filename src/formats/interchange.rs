use crate::core::{
    crypto::Crypto,
    limits::{
        MAX_DESCRIPTION_BYTES, MAX_ENTRIES, MAX_NAME_BYTES, MAX_PASSWORD_BYTES,
        MIN_ACCOUNT_PASSWORD_LENGTH,
    },
    password::Password,
    tags::TagValidator,
    types::{EncryptedExport, ExportData, ExportEntry},
    validation::Validation,
};
use zeroize::{Zeroize, Zeroizing};

pub const FORMAT_VERSION: &str = "4.0.0";
pub const CSV_HEADER: &str = "name,password,description,tags";

const CSV_FIELD_COUNT: usize = 4;
const CSV_FIELDS: [&str; CSV_FIELD_COUNT] = ["name", "password", "description", "tags"];
const TAG_SEPARATOR: &str = ";";
const BYTE_ORDER_MARK: char = '\u{feff}';

#[must_use]
pub fn would_fail_import(entry: &ExportEntry) -> bool {
    Validation::check_account_name(&entry.name).is_err()
        || entry.password.chars().count() < MIN_ACCOUNT_PASSWORD_LENGTH
        || entry
            .description
            .as_deref()
            .is_some_and(|description| Validation::check_description_text(description).is_err())
}

pub fn validate_import(entry: &mut ExportEntry) -> Result<(), String> {
    Validation::check_account_name(&entry.name)?;
    Password::length_check(&entry.password, MIN_ACCOUNT_PASSWORD_LENGTH)
        .map_err(|error| error.to_string())?;

    if let Some(description) = entry.description.as_deref() {
        Validation::check_description_text(description)?;
    }

    validate_stored(entry)
}

pub fn validate_stored(entry: &mut ExportEntry) -> Result<(), String> {
    if entry.name.trim().is_empty() || entry.name.len() > MAX_NAME_BYTES {
        return Err("Invalid or empty account name".to_string());
    }

    if entry.name.starts_with("__") {
        return Err("Reserved account name".to_string());
    }

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

pub fn parse_encrypted(bytes: &[u8]) -> Result<EncryptedExport, String> {
    let file: EncryptedExport = serde_json::from_slice(bytes).map_err(|error| {
        format!("Unsupported import file, expected an encrypted export or a CSV export: {error}")
    })?;

    if file.version != FORMAT_VERSION {
        return Err(format!("Unsupported export version: {}", file.version));
    }

    Ok(file)
}

pub fn open_encrypted(
    passphrase: &Zeroizing<String>,
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

#[must_use]
pub fn is_csv(text: &str) -> bool {
    strip_byte_order_mark(text).lines().next() == Some(CSV_HEADER)
}

pub fn encode_csv(entries: &[ExportEntry]) -> Result<Vec<u8>, String> {
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(Vec::new());

    writer
        .write_record(CSV_FIELDS)
        .map_err(|error| csv_error(&error))?;

    for entry in entries {
        let tags = entry.tags.join(TAG_SEPARATOR);
        writer
            .write_record([
                entry.name.as_str(),
                entry.password.as_str(),
                entry.description.as_deref().unwrap_or(""),
                tags.as_str(),
            ])
            .map_err(|error| csv_error(&error))?;
    }

    writer
        .into_inner()
        .map_err(|error| format!("Failed to build CSV output: {}", error.error()))
}

pub fn decode_csv(text: &str) -> Result<Vec<ExportEntry>, String> {
    let text = strip_byte_order_mark(text);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());

    let mut records = reader.records();
    let header = records
        .next()
        .ok_or_else(|| "Empty CSV file".to_string())?
        .map_err(|error| csv_error(&error))?;

    if !header.iter().eq(CSV_FIELDS) {
        return Err("Unrecognized CSV header".to_string());
    }

    let mut entries = Vec::new();

    for (index, record) in records.enumerate() {
        let row = index + 2;
        let record = record.map_err(|error| csv_error(&error))?;
        let entry = parse_csv_row(&record, row)?;

        if entries.len() == MAX_ENTRIES {
            return Err(format!("Too many entries (limit is {MAX_ENTRIES})"));
        }
        entries.push(entry);
    }

    Ok(entries)
}

fn parse_csv_row(record: &csv::StringRecord, row: usize) -> Result<ExportEntry, String> {
    let fields: [&str; CSV_FIELD_COUNT] =
        record
            .iter()
            .collect::<Vec<&str>>()
            .try_into()
            .map_err(|fields: Vec<&str>| {
                format!(
                    "Row {row} has {} fields, expected {CSV_FIELD_COUNT}",
                    fields.len()
                )
            })?;
    let [name, password, description, tags] = fields;

    Ok(ExportEntry {
        name: name.to_string(),
        password: password.to_string(),
        description: (!description.is_empty()).then(|| description.to_string()),
        tags: if tags.is_empty() {
            Vec::new()
        } else {
            tags.split(TAG_SEPARATOR).map(str::to_string).collect()
        },
    })
}

fn strip_byte_order_mark(text: &str) -> &str {
    text.strip_prefix(BYTE_ORDER_MARK).unwrap_or(text)
}

fn csv_error(error: &csv::Error) -> String {
    format!("Invalid CSV data: {error}")
}
