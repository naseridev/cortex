use crate::{
    core::types::SecureString,
    modules::{clipboard::Clipboard, gateway::Gateway},
};

pub struct Get;

impl Get {
    pub fn new(name: String, clip: Option<Option<u64>>) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        match storage.get_password(&name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(&entry)?;
                let password = SecureString::new(String::from_utf8(decrypted)?);
                let description = crypto.decrypt_description(&entry)?;

                if let Some(duration) = clip {
                    let seconds = duration.unwrap_or(43);
                    Clipboard::copy(password.as_str())?;

                    if seconds > 540 || seconds < 3 {
                        return Err("The time to be distracted is only allowed to be between 3 and 540 seconds".into());
                    }

                    println!("\nPassword copied to clipboard for {} seconds...", seconds);

                    if let Some(desc) = description {
                        println!("Description: {}", desc);
                    }

                    if Clipboard::clear(seconds, password.as_str()) {
                        println!("Done.");
                    } else {
                        return Err("The operation was not performed correctly".into());
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
