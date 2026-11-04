use crate::{
    core::{
        crypto::Crypto, dump::Dump, limits::MAX_DUMP_BYTES, storage::Storage,
        validation::Validation,
    },
    modules::{gateway::Gateway, security::Security, session::Session},
    ui::prompt::UserPrompt,
};
use std::{fs, path::Path};

pub fn execute(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    Validation::storage_probe(true, "No accounts found. Create one with 'account create'.")?;

    let path = Path::new(file_path);
    let size = fs::metadata(path)
        .map_err(|_| format!("File not found: {file_path}"))?
        .len();
    if size > MAX_DUMP_BYTES {
        return Err("Dump file is too large".into());
    }

    let bytes = fs::read(path).map_err(|error| format!("Failed to read {file_path}: {error}"))?;
    let file = Dump::decode(&bytes)?;

    let (storage, current_crypto) = Gateway::login_for_recovery()?;

    let (snapshot, dump_crypto) = if let Ok(snapshot) = Storage::read_dump(&file, &current_crypto) {
        (snapshot, current_crypto)
    } else {
        let password = UserPrompt::password("Master password used when this dump was created: ")?;
        let crypto = Crypto::open(&password, &file.salt)?;
        let snapshot = Storage::read_dump(&file, &crypto)?;
        (snapshot, crypto)
    };

    println!(
        "Dump is valid and contains {} entries.",
        snapshot.user_count()
    );

    Security::confirmation(
        "This replaces everything currently stored in the database with the contents of this dump.",
    )?;

    storage.replace_with_dump(&snapshot)?;
    storage.bind_integrity(&dump_crypto);
    storage.verify_integrity()?;

    Session::clear_session()?;

    println!("Database restored from dump.");
    println!("Unlock it with the master password that was active when the dump was created.");

    Ok(())
}
