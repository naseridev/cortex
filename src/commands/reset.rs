use crate::{
    core::{
        crypto::{Crypto, get_test_data},
        types::SecureString,
    },
    modules::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};

pub struct Reset;

impl Reset {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

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
            let password = String::from_utf8(decrypted)?;
            let description = crypto.decrypt_description(entry)?;
            decrypted_entries.push((name.clone(), SecureString::new(password), description));
        }

        for (name, password, description) in &decrypted_entries {
            let new_entry = Crypto::encrypt_with_new_key(
                &new_password,
                password.as_bytes(),
                description.as_deref(),
            )?;
            storage.update_entry(name, &new_entry)?;
        }

        let test_entry = Crypto::encrypt_with_new_key(&new_password, get_test_data(), None)?;
        storage.update_entry("__init__", &test_entry)?;
        storage.flush()?;

        println!("Master password reset.");

        Ok(())
    }
}
