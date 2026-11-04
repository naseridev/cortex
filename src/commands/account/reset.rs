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
use zeroize::{Zeroize, Zeroizing};

pub struct PlainEntry {
    pub name: String,
    pub password: Zeroizing<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub timestamp: u64,
}

impl Drop for PlainEntry {
    fn drop(&mut self) {
        if let Some(desc) = self.description.as_mut() {
            desc.zeroize();
        }
        for tag in &mut self.tags {
            tag.zeroize();
        }
    }
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

pub fn decrypt_all(
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
            timestamp: entry.timestamp,
        });
    }

    Ok(plain_entries)
}

pub fn reencrypt_all(
    plain_entries: &[PlainEntry],
    crypto: &Crypto,
) -> Result<Vec<(String, PasswordEntry)>, Box<dyn std::error::Error>> {
    let mut updated_entries = Vec::with_capacity(plain_entries.len());

    for plain in plain_entries {
        let tag_list = (!plain.tags.is_empty()).then_some(plain.tags.as_slice());
        let mut entry = crypto.create_entry(
            &plain.name,
            plain.password.as_bytes(),
            plain.description.as_deref(),
            tag_list,
        )?;
        entry.timestamp = plain.timestamp;

        updated_entries.push((plain.name.clone(), entry));
    }

    Ok(updated_entries)
}
