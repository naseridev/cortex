use crate::{
    core::{config::Config, crypto::Crypto, dump, limits::MAX_DUMP_BYTES, storage::Storage},
    modules::session::Session,
    ui::prompt::UserPrompt,
    modules::security::Security,
};
use std::{fs, path::Path};

pub struct Restore;

impl Restore {
    pub fn execute(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(file_path);
        let size = fs::metadata(path)
            .map_err(|_| format!("File not found: {file_path}"))?
            .len();
        if size > MAX_DUMP_BYTES {
            return Err("Dump file is too large".into());
        }

        let bytes =
            fs::read(path).map_err(|error| format!("Failed to read {file_path}: {error}"))?;
        let file = dump::decode(&bytes)?;

        let password = UserPrompt::password("Master password used when this dump was created: ")?;
        let crypto = Crypto::open(&password, &file.salt)?;
        let snapshot = Storage::read_dump(&file, &crypto)?;
        println!(
            "Dump is valid and contains {} entries.",
            snapshot.user_count()
        );

        Security::confirmation(
            "This replaces everything currently stored in the database with the contents of this dump.",
        )?;

        let storage = Storage::new()?;
        storage.replace_with_dump(&snapshot)?;
        Session::clear_session()?;
        Config::clear_cache();

        println!("Database restored from dump.");
        println!("Unlock it with the master password that was active when the dump was created.");

        Ok(())
    }
}
