use crate::{
    core::{crypto::Crypto, types::decode_secret_text},
    core::password::Password,
    modules::{gateway::Gateway, session::Session},
    ui::prompt::UserPrompt,
};
use zeroize::Zeroizing;

pub struct Reset;

impl Reset {
    pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login_for_recovery()?;

        if storage.verify_integrity().is_err() {
            eprintln!(
                "Warning: the vault had no valid integrity record. The reset rebuilds it from the current contents, so review your entries afterwards."
            );
        }

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
            let decrypted = crypto.decrypt_entry(name, entry)?;
            let password = Zeroizing::new(decode_secret_text(decrypted)?);
            let description = crypto.decrypt_description(name, entry)?;
            let tags = crypto.decrypt_tags(name, entry)?;
            decrypted_entries.push((name.clone(), password, description, tags));
        }

        let (new_crypto, new_salt) = Crypto::create(&new_password)?;

        let mut updated_entries = Vec::with_capacity(decrypted_entries.len());
        for (name, password, description, tags) in &decrypted_entries {
            let tag_list = if tags.is_empty() {
                None
            } else {
                Some(tags.as_slice())
            };

            let new_entry = new_crypto.create_entry(
                name,
                password.as_bytes(),
                description.as_deref(),
                tag_list,
            )?;
            updated_entries.push((name.clone(), new_entry));
        }

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
}
