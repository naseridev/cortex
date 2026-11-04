use crate::core::{
    crypto::Crypto,
    dump::{Dump, DumpFile},
    integrity::{Integrity, MANIFEST_KEY, Records},
    platform::Platform,
    storage::{INIT_MARKER, SALT_KEY, Storage},
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const DUMP_PREFIX: &str = "dump_";
const DUMP_SUFFIX: &str = ".bin";
const INVALID_DUMP_MESSAGE: &str = "Dump content is invalid or damaged.";
const WRONG_PASSWORD_OR_DAMAGED_MESSAGE: &str = "Wrong master password or damaged dump file.";
const DUMP_HEADER_MISMATCH_MESSAGE: &str = "Dump header does not match its contents.";
const DUMP_INTEGRITY_MESSAGE: &str = "Dump integrity check failed.";

pub struct Snapshot {
    pub(crate) entries: Records,
    user_count: usize,
}

impl Snapshot {
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.user_count
    }

    #[must_use]
    pub fn entries(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.entries
    }

    pub fn from_dump(file: &DumpFile, crypto: &Crypto) -> Result<Self, Box<dyn std::error::Error>> {
        let mut plain = crypto
            .open_dump(&file.nonce, &file.ciphertext)
            .map_err(|_| WRONG_PASSWORD_OR_DAMAGED_MESSAGE)?;

        let parsed: Result<Records, String> = Storage::decode_value(&plain);
        plain.zeroize();

        let entries = parsed.map_err(|_| INVALID_DUMP_MESSAGE)?;
        let find = |key: &str| -> Option<&[u8]> {
            entries
                .iter()
                .find(|(name, _)| name.as_slice() == key.as_bytes())
                .map(|(_, value)| value.as_slice())
        };

        let init = find(INIT_MARKER).ok_or(INVALID_DUMP_MESSAGE)?;
        let salt = find(SALT_KEY).ok_or(INVALID_DUMP_MESSAGE)?;
        let manifest = find(MANIFEST_KEY).ok_or(INVALID_DUMP_MESSAGE)?;

        if salt != file.salt.as_slice() {
            return Err(DUMP_HEADER_MISMATCH_MESSAGE.into());
        }

        if !crypto.matches_verification(init) {
            return Err(WRONG_PASSWORD_OR_DAMAGED_MESSAGE.into());
        }

        let stored_manifest = <[u8; 32]>::try_from(manifest).map_err(|_| INVALID_DUMP_MESSAGE)?;
        let expected = Integrity::snapshot_digest(&crypto.integrity_key(), &entries);

        if blake3::Hash::from(stored_manifest) != expected {
            return Err(DUMP_INTEGRITY_MESSAGE.into());
        }

        let user_count = entries
            .iter()
            .filter(|(name, _)| !Integrity::is_reserved_key(name))
            .count();

        Ok(Self {
            entries,
            user_count,
        })
    }

    pub fn encode_bytes(
        storage: &Storage,
        crypto: &Crypto,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let salt = storage
            .get_salt()?
            .ok_or("Database salt not found. Database may be corrupted.")?;

        let records = storage.records()?;
        let mut plain = Storage::encode_value(&records)?;
        drop(records);

        let sealed = crypto.seal_dump(&plain);
        plain.zeroize();

        let (ciphertext, nonce) = sealed?;
        let bytes = Dump::encode(&DumpFile {
            salt,
            nonce,
            ciphertext,
        })?;

        Ok(bytes)
    }

    pub fn write_to_dir(
        storage: &Storage,
        dump_dir: &Path,
        crypto: &Crypto,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        fs::create_dir_all(dump_dir).map_err(|error| {
            format!("Failed to create directory {}: {error}", dump_dir.display())
        })?;

        let bytes = Self::encode_bytes(storage, crypto)?;

        let path = dump_dir.join(format!(
            "{DUMP_PREFIX}{:020}{DUMP_SUFFIX}",
            Self::dump_stamp()
        ));

        Self::write_new_file(&path, &bytes)?;
        Ok(path)
    }

    fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let directory = path.parent().unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            format!("Failed to create dump in {}: {error}", directory.display())
        })?;

        temp.write_all(bytes)
            .map_err(|error| format!("Failed to write dump {}: {error}", path.display()))?;
        temp.as_file()
            .sync_all()
            .map_err(|error| format!("Failed to write dump {}: {error}", path.display()))?;

        Platform::restrict_to_owner(temp.path())
            .map_err(|error| format!("Failed to set permissions on {}: {error}", path.display()))?;
        temp.persist_noclobber(path)
            .map_err(|error| format!("Failed to save dump {}: {}", path.display(), error.error))?;

        Ok(())
    }

    fn dump_stamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    }
}
