use super::resolve_name;
use crate::{
    core::{
        accounts::Accounts,
        crypto::Crypto,
        password::Password,
        types::{PasswordEntry, SecretText},
        validation::Validation,
    },
    modules::{gateway::Gateway, session::Session},
    ui::prompt::UserPrompt,
};
use zeroize::Zeroizing;

struct PlainEntry {
    name: String,
    password: Zeroizing<String>,
    description: Option<String>,
    tags: Vec<String>,
}

pub fn execute(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (accounts, _) = Accounts::list()?;
    if accounts.is_empty() {
        return Err("No accounts found. Create one with 'account create'.".into());
    }

    let account_name = resolve_name(name, "Account name: ")?;
    Validation::check_account_name(&account_name)?;

    if !Accounts::exists(&account_name)? {
        return Err(format!("Account '{account_name}' not found.").into());
    }

    perform_reset(&account_name)
}

fn perform_reset(account_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login_account_for_recovery(account_name)?;

    if storage.verify_integrity().is_err() {
        eprintln!(
            "Warning: the vault had no valid integrity record. The reset rebuilds it from the current contents, so review your entries afterwards."
        );
    }

    let new_password = prompt_new_master_password()?;
    let confirm_password = UserPrompt::password("Confirm new password: ")?;
    Password::match_check(new_password.as_str(), confirm_password.as_str())?;

    let stored_entries = storage.get_all_entries()?;
    let plain_entries = decrypt_all(&stored_entries, &crypto)?;

    let (new_crypto, new_salt) = Crypto::create(&new_password)?;
    let updated_entries = reencrypt_all(&plain_entries, &new_crypto)?;

    storage.atomic_reset(&updated_entries, &new_crypto, &new_salt)?;

    if Accounts::is_agent(account_name)? {
        Accounts::update_agent_key(account_name, new_crypto.key())?;
    }

    if Accounts::active()?.as_deref() == Some(account_name) {
        Session::clear_session()?;
    }

    println!("Master password reset successfully for account '{account_name}'.");
    println!(
        "Account passwords were not changed. Change the password of every stored account now."
    );

    println!("Passwords stored in this vault may already be exposed if someone else accessed it.");

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
        let password = Zeroizing::new(SecretText::decode(crypto.decrypt_entry(name, entry)?)?);
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

#[cfg(test)]
mod tests {
    use super::{decrypt_all, reencrypt_all};
    use crate::core::crypto::Crypto;

    #[test]
    fn reencryption_keeps_name_password_description_and_tags()
    -> Result<(), Box<dyn std::error::Error>> {
        let old_crypto = Crypto::from_key([7u8; 32]);
        let new_crypto = Crypto::from_key([8u8; 32]);
        let tags = vec!["mail".to_string(), "work".to_string()];
        let stored = vec![(
            "alpha".to_string(),
            old_crypto.create_entry("alpha", b"secret123", Some("desc"), Some(tags.as_slice()))?,
        )];

        let plain = decrypt_all(&stored, &old_crypto)?;
        let reencrypted = reencrypt_all(&plain, &new_crypto)?;
        let restored = decrypt_all(&reencrypted, &new_crypto)?;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].name, "alpha");
        assert_eq!(restored[0].password.as_str(), "secret123");
        assert_eq!(restored[0].description.as_deref(), Some("desc"));
        assert_eq!(restored[0].tags, tags);
        Ok(())
    }
}
