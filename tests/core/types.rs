use cortex::core::limits::MAX_ENTRIES;
use cortex::core::types::{ExportData, ExportEntry, SecretText};

fn sample_entries(count: usize) -> Vec<ExportEntry> {
    (0..count)
        .map(|index| ExportEntry {
            name: format!("entry{index}"),
            password: "password123".to_string(),
            description: None,
            tags: Vec::new(),
        })
        .collect()
}

fn payload_bytes(count: usize) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&ExportData {
        version: "4.0.0".to_string(),
        timestamp: 1,
        entries: sample_entries(count),
    })
}

#[test]
fn secret_text_decodes_utf8_and_rejects_invalid_bytes() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(SecretText::decode(b"hunter2".to_vec())?, "hunter2");
    assert!(SecretText::decode(vec![0xff, 0xfe]).is_err());
    Ok(())
}

#[test]
fn export_payload_accepts_exactly_the_entry_limit() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = payload_bytes(MAX_ENTRIES)?;
    let parsed: ExportData = serde_json::from_slice(&bytes)?;
    assert_eq!(parsed.entries.len(), MAX_ENTRIES);
    Ok(())
}

#[test]
fn export_payload_rejects_more_than_the_entry_limit() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = payload_bytes(MAX_ENTRIES + 1)?;
    assert!(serde_json::from_slice::<ExportData>(&bytes).is_err());
    Ok(())
}
