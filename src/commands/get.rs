use crate::{
    core::types::{SecureString, decode_secret_text},
    modules::{clipboard::Clipboard, gateway::Gateway},
};

pub struct Get;

impl Get {
    pub fn execute(
        name: &str,
        clip: Option<Option<u64>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        match storage.get_password(name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(name, &entry)?;
                let password = SecureString::new(decode_secret_text(decrypted)?);
                let description = crypto.decrypt_description(name, &entry)?;
                let tags = crypto.decrypt_tags(name, &entry)?;

                if let Some(duration) = clip {
                    let seconds = duration.unwrap_or(43);

                    if !(3..=540).contains(&seconds) {
                        return Err("Clipboard timeout must be between 3 and 540 seconds".into());
                    }

                    Clipboard::copy(password.as_str())?;

                    println!("\nPassword copied to clipboard for {seconds} seconds...");

                    if let Some(desc) = description {
                        println!("Description: {desc}");
                    }
                    if !tags.is_empty() {
                        println!("Tags: {}", tags.join(", "));
                    }

                    if Clipboard::clear(seconds, password.as_str())? {
                        println!("Clipboard cleared.");
                    } else {
                        return Err("Failed to clear clipboard properly".into());
                    }
                } else {
                    println!();
                    println!("{}: {}", name, password.as_str());
                    if let Some(desc) = description {
                        println!("Description: {desc}");
                    }
                    if !tags.is_empty() {
                        println!("Tags: {}", tags.join(", "));
                    }
                }
            }
            None => return Err(format!("Not found: {name}").into()),
        }

        Ok(())
    }
}
