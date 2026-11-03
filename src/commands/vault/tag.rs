pub mod add;
pub mod list;
pub mod remove;

use crate::{
    core::{
        crypto::Crypto,
        storage::Storage,
        tags::TagValidator,
        types::{PasswordEntry, SecretText},
    },
    ui::cli::TagAction,
};
use zeroize::Zeroizing;

pub fn run(action: TagAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        TagAction::List => list::execute(),
        TagAction::Add { name, tags } => add::execute(&name, &TagValidator::parse_input(&tags)),
        TagAction::Remove { name, tags } => {
            remove::execute(&name, &TagValidator::parse_input(&tags))
        }
    }
}

fn load_entry(storage: &Storage, name: &str) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let entry = storage
        .get_password(name)?
        .ok_or_else(|| format!("Entry '{name}' not found"))?;
    Ok(entry)
}

fn rewrite_entry(
    storage: &Storage,
    crypto: &Crypto,
    name: &str,
    entry: &PasswordEntry,
    tags: Option<&[String]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let decrypted = crypto.decrypt_entry(name, entry)?;
    let password = Zeroizing::new(SecretText::decode(decrypted)?);
    let description = crypto.decrypt_description(name, entry)?;

    let updated = crypto.create_entry(name, password.as_bytes(), description.as_deref(), tags)?;
    if !storage.edit_password(name, &updated)? {
        return Err(format!("Failed to update entry '{name}'").into());
    }

    Ok(())
}
