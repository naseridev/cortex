use crate::core::{config::Config, crypto::Crypto, time::Time, types::SecureString};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

const SESSION_FILE: &str = ".cortex_session";
const MAX_SESSION_AGE: u64 = 86400;
const SESSION_KDF_ITERATIONS: u32 = 300_000;

#[derive(Debug, Serialize, Deserialize)]
struct SessionData {
    timestamp: u64,
    nonce: [u8; 12],
    salt: [u8; 32],
    encrypted_password: Vec<u8>,
    attempts: u32,
    machine_hash: [u8; 32],
}

pub struct Session;

impl Session {
    pub fn save_session(master_password: &SecureString) -> Result<(), Box<dyn std::error::Error>> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let mut session_key = Self::derive_session_key(&salt);
        let cipher = ChaCha20Poly1305::new(&session_key);
        session_key.as_mut_slice().zeroize();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, master_password.as_bytes())
            .map_err(|_| "Session encryption failed")?;

        let timestamp = Time::current_timestamp();
        let machine_hash = Self::compute_machine_hash();

        let session_data = SessionData {
            timestamp,
            nonce: nonce_bytes,
            salt,
            encrypted_password: encrypted,
            attempts: 0,
            machine_hash,
        };

        let serialized = bincode::serialize(&session_data)?;

        let session_path = Self::get_session_path();
        let mut file = File::create(&session_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&session_path, fs::Permissions::from_mode(0o600))?;
        }

        file.write_all(&serialized)?;
        file.sync_all()?;

        Ok(())
    }

    pub fn load_session() -> Result<Option<SecureString>, Box<dyn std::error::Error>> {
        let session_path = Self::get_session_path();

        if !session_path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&session_path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        drop(file);

        let Ok(session_data) = bincode::deserialize::<SessionData>(&contents) else {
            Self::clear_session()?;
            return Ok(None);
        };

        if session_data.encrypted_password.is_empty() {
            Self::clear_session()?;
            return Ok(None);
        }

        let current_machine_hash = Self::compute_machine_hash();
        if session_data.machine_hash != current_machine_hash {
            Self::clear_session()?;
            return Ok(None);
        }

        let current_time = Time::current_timestamp();
        let config = Config::load()?;

        let elapsed = current_time.saturating_sub(session_data.timestamp);

        if elapsed > config.session_timeout_seconds || elapsed > MAX_SESSION_AGE {
            Self::clear_session()?;
            return Ok(None);
        }

        if session_data.attempts >= 3 {
            Self::clear_session()?;
            return Err("Too many failed session validation attempts".into());
        }

        let mut session_key = Self::derive_session_key(&session_data.salt);
        let cipher = ChaCha20Poly1305::new(&session_key);
        session_key.as_mut_slice().zeroize();

        let nonce = Nonce::from_slice(&session_data.nonce);

        let Ok(decrypted) = cipher.decrypt(nonce, session_data.encrypted_password.as_ref()) else {
            Self::clear_session()?;
            return Ok(None);
        };

        let password = match String::from_utf8(decrypted) {
            Ok(p) => p,
            Err(e) => {
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                Self::clear_session()?;
                return Ok(None);
            }
        };

        let secure_password = SecureString::new(password);

        Self::save_session(&secure_password)?;

        Ok(Some(secure_password))
    }

    pub fn clear_session() -> Result<(), Box<dyn std::error::Error>> {
        let session_path = Self::get_session_path();
        if session_path.exists() {
            let metadata = fs::metadata(&session_path)?;
            let file_size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);

            if file_size > 0 && file_size < 1024 * 1024 {
                let mut file = File::options().write(true).open(&session_path)?;
                let zeros = vec![0u8; file_size];
                file.write_all(&zeros)?;
                file.sync_all()?;
            }

            fs::remove_file(&session_path)?;
        }
        Ok(())
    }

    fn derive_session_key(salt: &[u8; 32]) -> Key {
        let hardware_id = Crypto::get_hardware_id();

        let mut hasher = Hasher::new();
        hasher.update(hardware_id);
        hasher.update(b"cortex_session_key_v3");
        hasher.update(salt);

        let mut derived = *hasher.finalize().as_bytes();

        for _ in 0..SESSION_KDF_ITERATIONS {
            let mut hasher = Hasher::new();
            hasher.update(&derived);
            hasher.update(salt);
            derived = *hasher.finalize().as_bytes();
        }

        let key = Key::from(derived);
        derived.zeroize();
        key
    }

    fn compute_machine_hash() -> [u8; 32] {
        let hardware_id = Crypto::get_hardware_id();

        let mut hasher = Hasher::new();
        hasher.update(hardware_id);
        hasher.update(b"cortex_machine_binding_v1");

        *hasher.finalize().as_bytes()
    }

    fn get_session_path() -> PathBuf {
        let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("cortex");
        fs::create_dir_all(&path).ok();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
        }

        path.push(SESSION_FILE);
        path
    }
}

impl Drop for SessionData {
    fn drop(&mut self) {
        self.encrypted_password.zeroize();
        self.nonce.zeroize();
        self.salt.zeroize();
        self.machine_hash.zeroize();
    }
}
