use crate::{
    core::{types::decode_secret_text, validation::Validation},
    modules::{clipboard, gateway::Gateway},
};
use zeroize::Zeroizing;

const CLIPBOARD_SECONDS: u64 = 60;

pub fn execute(name: &str, show: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login_with_session()?;

    let Some(entry) = storage.get_password(name)? else {
        return Err(format!("Not found: {name}").into());
    };

    let password = Zeroizing::new(decode_secret_text(crypto.decrypt_entry(name, &entry)?)?);
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

    Ok(())
}
