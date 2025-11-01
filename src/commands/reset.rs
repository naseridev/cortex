use crate::{
    core::{crypto::Crypto, types::SecureString},
    modules::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};

pub struct Reset;

impl Reset {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let salt = storage.get_salt()?.ok_or("Database salt not found")?;

        let new_password = loop {
            let password = UserPrompt::password("New master password: ")?;

            match Password::security_check(password.as_str()) {
                Ok(_) => {
                    break password;
                }
                Err(msg) => {
                    eprintln!("Error: {}\n", msg);
                }
            }
        };

        let confirm_password = UserPrompt::password("Confirm new password: ")?;

        Password::match_check(new_password.as_str(), confirm_password.as_str())?;

        let entries = storage.get_all_entries()?;
        let mut decrypted_entries = Vec::new();

        for (name, entry) in &entries {
            let decrypted = crypto.decrypt_entry(entry)?;
            let password_str = String::from_utf8(decrypted)?;
            let password = SecureString::new(password_str);
            let description = crypto.decrypt_description(entry)?;
            let tags = crypto.decrypt_tags(entry)?;
            decrypted_entries.push((name.clone(), password, description, tags));
        }

        let new_crypto = Crypto::new(&new_password, &salt);

        for (name, password, description, tags) in &decrypted_entries {
            let tag_list = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };

            let new_entry =
                new_crypto.create_entry(password.as_bytes(), description.as_deref(), tag_list)?;
            storage.update_entry(name, &new_entry)?;
        }

        let verification_data = Crypto::create_verification_data(&new_password, &salt);
        storage.update_entry(
            "__init__",
            &crate::core::types::PasswordEntry {
                encrypted_password: verification_data,
                encrypted_description: None,
                encrypted_tags: None,
                nonce: [0u8; 12],
                desc_nonce: None,
                tags_nonce: None,
                timestamp: crate::core::time::Time::current_timestamp(),
            },
        )?;

        storage.flush()?;

        println!("Master password reset.");

        Ok(())
    }
}
