use crate::{
    core::types::decode_secret_text,
    core::validation::Validation,
    modules::{clipboard, gateway::Gateway},
};
use zeroize::Zeroizing;

const CLIPBOARD_SECONDS: u64 = 30;

pub struct Get;

impl Get {
    pub fn execute(name: &str, show: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login_with_session()?;

        match storage.get_password(name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(name, &entry)?;
                let password = Zeroizing::new(decode_secret_text(decrypted)?);
                let description = crypto.decrypt_description(name, &entry)?;
                let tags = crypto.decrypt_tags(name, &entry)?;

                println!();
                if show {
                    println!("{}: {}", Validation::printable(name), password.as_str());
                }
                if let Some(desc) = description {
                    println!("Description: {}", Validation::printable(&desc));
                }
                if !tags.is_empty() {
                    println!("Tags: {}", tags.join(", "));
                }
                if !show {
                    clipboard::copy_then_clear(password.as_str(), CLIPBOARD_SECONDS)?;
                }
            }
            None => return Err(format!("Not found: {name}").into()),
        }

        Ok(())
    }
}
