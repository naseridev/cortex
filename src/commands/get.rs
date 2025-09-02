use crate::{
    core::{crypto::Crypto, storage::Storage},
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Get;

impl Get {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        if !Storage::get_db_path().exists() {
            eprintln!("Database not initialized. Use 'init' command.");
            process::exit(1);
        }

        let master_password = UserPrompt::password("Master password: ")?;

        let crypto = Crypto::new(&master_password);
        let storage = Storage::new()?;

        let result = match storage.get_init_marker()? {
            Some(entry) => crypto.verify_test_data(&entry),
            None => false,
        };

        if !result {
            return Err("Authentication failed".into());
        }

        match storage.get_password(&name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(&entry)?;
                let password = String::from_utf8(decrypted)?;
                let description = crypto.decrypt_description(&entry)?;

                println!();
                println!("{}: {}", name, password.as_str());
                if let Some(desc) = description {
                    println!("Description: {}", desc);
                }
            }
            None => println!("Not found: {}", name),
        };

        Ok(())
    }
}
