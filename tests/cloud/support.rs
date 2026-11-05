use cortex::core::{crypto::Crypto, types::PasswordEntry};

pub fn sample_entry(
    crypto: &Crypto,
    name: &str,
    pass: &str,
    timestamp: u64,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let mut entry = crypto.create_entry(name, pass.as_bytes(), None, None)?;
    entry.timestamp = timestamp;
    Ok(entry)
}
