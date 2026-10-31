use crate::{
    core::types::{SecureString, decode_secret_text},
    modules::gateway::Gateway,
};

pub struct Get;

impl Get {
    pub fn execute(name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        match storage.get_password(name)? {
            Some(entry) => {
                let decrypted = crypto.decrypt_entry(name, &entry)?;
                let password = SecureString::new(decode_secret_text(decrypted)?);
                let description = crypto.decrypt_description(name, &entry)?;
                let tags = crypto.decrypt_tags(name, &entry)?;

                println!();
                println!("{}: {}", name, password.as_str());
                if let Some(desc) = description {
                    println!("Description: {desc}");
                }
                if !tags.is_empty() {
                    println!("Tags: {}", tags.join(", "));
                }
            }
            None => return Err(format!("Not found: {name}").into()),
        }

        Ok(())
    }
}
