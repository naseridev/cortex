use crate::{
    domain::{
        limits::{MAX_DESCRIPTION_BYTES, MIN_ACCOUNT_PASSWORD_LENGTH},
        tags::TagValidator,
        types::SecretText,
        validation::Validation,
    },
    security::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};
use zeroize::Zeroizing;

pub fn execute(name: &str, tags: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    if Validation::is_reserved_or_blank(name) {
        return Err("Cannot edit system or empty entries".into());
    }

    let (storage, crypto) = Gateway::login()?;
    let entry = storage
        .get_password(name)?
        .ok_or_else(|| format!("Account '{name}' not found."))?;

    let current_password = Zeroizing::new(SecretText::decode(crypto.decrypt_entry(name, &entry)?)?);
    let current_description = crypto
        .decrypt_description(name, &entry)?
        .map(Zeroizing::new);

    let current_tags = crypto.decrypt_tags(name, &entry)?;
    let new_password = prompt_new_password(&current_password)?;

    let description_input = Zeroizing::new(UserPrompt::text_with_limit(
        "New description (Enter to keep current): ",
        MAX_DESCRIPTION_BYTES,
    )?);

    let current_description_text = current_description.as_ref().map(|value| value.as_str());
    let description = resolve_description(description_input.as_str(), current_description_text)?;

    if let Some(text) = description {
        Password::in_desc_check(new_password.as_str(), text)?;
    }

    let tag_list = match tags {
        Some(raw) => Some(TagValidator::parse_and_validate(&raw)?),
        None => (!current_tags.is_empty()).then(|| current_tags.clone()),
    };

    let current_tag_list = (!current_tags.is_empty()).then_some(&current_tags);
    let no_changes = new_password.as_str() == current_password.as_str()
        && description == current_description_text
        && tag_list.as_ref() == current_tag_list;

    if no_changes {
        println!("No changes made to '{name}'.");
        return Ok(());
    }

    let updated_entry = crypto.create_entry(
        name,
        new_password.as_bytes(),
        description,
        tag_list.as_deref(),
    )?;

    if !storage.edit_password(name, &updated_entry)? {
        return Err(format!("Account '{name}' not found.").into());
    }

    println!("Edited '{name}'.");
    Ok(())
}

fn prompt_new_password(
    current_password: &Zeroizing<String>,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let Some(input) = UserPrompt::optional_password("New password (Enter to keep current): ")?
    else {
        return Ok(Zeroizing::new(current_password.as_str().to_string()));
    };

    Password::length_check(input.as_str(), MIN_ACCOUNT_PASSWORD_LENGTH)?;
    let confirmation = UserPrompt::password("Confirm new password: ")?;

    Password::match_check(input.as_str(), confirmation.as_str())?;
    Ok(input)
}

fn resolve_description<'a>(
    input: &'a str,
    current: Option<&'a str>,
) -> Result<Option<&'a str>, Box<dyn std::error::Error>> {
    if input.is_empty() {
        return Ok(current);
    }

    Validation::check_description_text(input)?;
    Ok(Some(input))
}
