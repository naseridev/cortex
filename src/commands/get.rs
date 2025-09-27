use crate::{
    core::{crypto::Crypto, storage::Storage},
    modules::{clipboard::Clipboard, validation::Validation},
    ui::prompt::UserPrompt,
};
use std::process;

pub struct Get;

impl Get {
    pub fn new(name: String, clip: Option<Option<u64>>) -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_existence_probe()?;

        let mut failure = 0;

        let (storage, crypto) = loop {
            let master_password = UserPrompt::password("Master password: ")?;
            let crypto = Crypto::new(&master_password);
            let storage_attempt = Storage::new()?;

            let is_correct = match storage_attempt.get_init_marker()? {
                Some(entry) => crypto.verify_test_data(&entry),
                None => false,
            };

            if is_correct {
                break (storage_attempt, crypto);
            } else if failure > 1 {
                return Err("Authentication failed".into());
            } else {
                eprintln!("Sorry, try again.\n");
                failure += 1;
            }
        };

        match storage.get_password(&name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(&entry)?;
                let password = String::from_utf8(decrypted)?;
                let description = crypto.decrypt_description(&entry)?;

                if let Some(duration) = clip {
                    let seconds = duration.unwrap_or(43);
                    Clipboard::copy(password.as_str())?;

                    if seconds > 540 || seconds < 3 {
                        eprintln!(
                            "Error: The time to be distracted is only allowed to be between 3 and 540 seconds"
                        );
                        process::exit(1);
                    }

                    println!();
                    println!("Password copied to clipboard for {} seconds...", seconds);

                    if let Some(desc) = description {
                        println!("Description: {}", desc);
                    }

                    if Clipboard::clear(seconds, password.as_str()) {
                        println!("Done.");
                    } else {
                        eprintln!("Error: The operation was not performed correctly");
                        process::exit(1);
                    }
                } else {
                    println!();
                    println!("{}: {}", name, password.as_str());
                    if let Some(desc) = description {
                        println!("Description: {}", desc);
                    }
                }
            }
            None => println!("Not found: {}", name),
        };

        Ok(())
    }
}
