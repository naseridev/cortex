use crate::{
    core::{crypto::Crypto, types::SecureString},
    modules::{gateway::Gateway, password::Password, session::Session},
    ui::prompt::UserPrompt,
};

pub struct Reset;

impl Reset {
    pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        println!("Creating backup before reset...");
        storage.create_backup()?;
        println!("Backup created successfully.\n");

        let new_password = loop {
            let password = UserPrompt::password("New master password: ")?;

            match Password::security_check(password.as_str()) {
                Ok(()) => break password,
                Err(msg) => eprintln!("Error: {msg}\n"),
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

        let new_salt = Crypto::generate_salt();
        let new_crypto = Crypto::new(&new_password, &new_salt);

        let mut updated_entries = Vec::with_capacity(decrypted_entries.len());
        for (name, password, description, tags) in &decrypted_entries {
            let tag_list = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };

            let new_entry =
                new_crypto.create_entry(password.as_bytes(), description.as_deref(), tag_list)?;
            updated_entries.push((name.clone(), new_entry));
        }

        let verification_data = Crypto::create_verification_data(&new_password, &new_salt);

        storage.atomic_reset(&updated_entries, &verification_data, &new_salt)?;
        let _ = Session::save_session(&new_password);

        println!("Master password reset successfully.");

        Ok(())
    }
}
