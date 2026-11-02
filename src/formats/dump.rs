const DUMP_VERSION: u8 = 3;
const PREVIOUS_DUMP_VERSION: u8 = 2;
const LEGACY_DUMP_VERSION: u8 = 1;
const SALT_LENGTH_BYTES: usize = 2;
const NONCE_BYTES: usize = 12;

pub struct DumpFile {
    pub salt: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

pub fn encode(file: &DumpFile) -> Result<Vec<u8>, String> {
    let salt_length = u16::try_from(file.salt.len())
        .map_err(|_| "Salt is too long for a dump file".to_string())?;
    let mut bytes = Vec::with_capacity(
        1 + SALT_LENGTH_BYTES + file.salt.len() + NONCE_BYTES + file.ciphertext.len(),
    );

    bytes.push(DUMP_VERSION);
    bytes.extend_from_slice(&salt_length.to_le_bytes());
    bytes.extend_from_slice(&file.salt);
    bytes.extend_from_slice(&file.nonce);
    bytes.extend_from_slice(&file.ciphertext);

    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<DumpFile, String> {
    let damaged = || "Unsupported or damaged dump file".to_string();
    let (&version, rest) = bytes.split_first().ok_or_else(damaged)?;

    if version == LEGACY_DUMP_VERSION {
        return Err(
            "This dump was made by the old backup format and cannot be restored".to_string(),
        );
    }

    if version == PREVIOUS_DUMP_VERSION {
        return Err(
            "This dump was made by an older cortex version and cannot be restored. Export it to CSV with that version and import the CSV here instead.".to_string(),
        );
    }

    if version != DUMP_VERSION {
        return Err(damaged());
    }

    if rest.len() < SALT_LENGTH_BYTES {
        return Err(damaged());
    }

    let (length_bytes, rest) = rest.split_at(SALT_LENGTH_BYTES);
    let salt_length = usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]));

    if rest.len() < salt_length + NONCE_BYTES {
        return Err(damaged());
    }

    let (salt, rest) = rest.split_at(salt_length);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_BYTES);

    if ciphertext.is_empty() {
        return Err(damaged());
    }

    let mut nonce = [0u8; NONCE_BYTES];

    nonce.copy_from_slice(nonce_bytes);
    Ok(DumpFile {
        salt: salt.to_vec(),
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}
