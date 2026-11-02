use crate::{
    core::{
        crypto::Crypto,
        password::Password,
        types::{PasswordEntry, decode_secret_text},
    },
    modules::{gateway::Gateway, session::Session},
    ui::prompt::UserPrompt,
};
use zeroize::Zeroizing;

pub struct Reset;

struct PlainEntry {
    name: String,
    password: Zeroizing<String>,
    description: Option<String>,
    tags: Vec<String>,
}

impl Reset {
    pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login_for_recovery()?;

        if storage.verify_integrity().is_err() {
            eprintln!(
                "Warning: the vault had no valid integrity record. The reset rebuilds it from the current contents, so review your entries afterwards."
            );
        }

        let new_password = Self::prompt_new_master_password()?;
        let confirm_password = UserPrompt::password("Confirm new password: ")?;
        Password::match_check(new_password.as_str(), confirm_password.as_str())?;

        let stored_entries = storage.get_all_entries()?;
        let plain_entries = Self::decrypt_all(&stored_entries, &crypto)?;

        let (new_crypto, new_salt) = Crypto::create(&new_password)?;
        let updated_entries = Self::reencrypt_all(&plain_entries, &new_crypto)?;

        storage.atomic_reset(&updated_entries, &new_crypto, &new_salt)?;
        Session::clear_session()?;

        println!("Master password reset successfully.");
        println!(
            "Account passwords were not changed. Change the password of every stored account now."
        );
        println!(
            "Passwords stored in this vault may already be exposed if someone else accessed it."
        );
        println!(
            "Dumps created earlier still require the master password that was active when they were made."
        );

        Ok(())
    }

    fn prompt_new_master_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        loop {
            let password = UserPrompt::password("New master password: ")?;

            match Password::security_check(password.as_str()) {
                Ok(()) => return Ok(password),
                Err(message) => eprintln!("Error: {message}\n"),
            }
        }
    }

    fn decrypt_all(
        stored_entries: &[(String, PasswordEntry)],
        crypto: &Crypto,
    ) -> Result<Vec<PlainEntry>, Box<dyn std::error::Error>> {
        let mut plain_entries = Vec::with_capacity(stored_entries.len());

        for (name, entry) in stored_entries {
            let password = Zeroizing::new(decode_secret_text(crypto.decrypt_entry(name, entry)?)?);
            let description = crypto.decrypt_description(name, entry)?;
            let tags = crypto.decrypt_tags(name, entry)?;

            plain_entries.push(PlainEntry {
                name: name.clone(),
                password,
                description,
                tags,
            });
        }

        Ok(plain_entries)
    }

    fn reencrypt_all(
        plain_entries: &[PlainEntry],
        crypto: &Crypto,
    ) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
        let mut updated_entries = Vec::with_capacity(plain_entries.len());

        for plain in plain_entries {
            let tag_list = (!plain.tags.is_empty()).then_some(plain.tags.as_slice());
            let entry = crypto.create_entry(
                &plain.name,
                plain.password.as_bytes(),
                plain.description.as_deref(),
                tag_list,
            )?;

            updated_entries.push((plain.name.clone(), entry));
        }

        Ok(updated_entries)
    }
}
