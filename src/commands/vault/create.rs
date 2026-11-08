use crate::{
    domain::{
        limits::{MAX_DESCRIPTION_BYTES, MIN_ACCOUNT_PASSWORD_LENGTH},
        tags::TagValidator,
        validation::Validation,
    },
    security::{gateway::Gateway, password::Password},
    ui::prompt::UserPrompt,
};
use zeroize::Zeroizing;

pub fn execute(name: &str, tags: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    Validation::check_account_name(name)?;

    let (storage, crypto) = Gateway::login_with_session()?;

    Validation::account_exists_probe(
        &storage,
        name,
        false,
        "Account already exists. Use 'edit' to update or choose a different name.",
    )?;

    let password = prompt_new_password()?;
    let description_input = Zeroizing::new(UserPrompt::text_with_limit(
        "Description (optional): ",
        MAX_DESCRIPTION_BYTES,
    )?);

    Validation::check_description_text(description_input.as_str())?;
    Password::in_desc_check(password.as_str(), description_input.as_str())?;

    let description = (!description_input.is_empty()).then_some(description_input.as_str());
    let tag_list = tags
        .map(|raw| TagValidator::parse_and_validate(&raw))
        .transpose()?;

    let entry = crypto.create_entry(name, password.as_bytes(), description, tag_list.as_deref())?;

    if !storage.create_password(name, &entry)? {
        return Err(format!(
            "Account '{name}' already exists. Use 'edit' to update or choose a different name."
        )
        .into());
    }

    println!("Created '{name}'.");

    if let Some(tags) = tag_list.filter(|list| !list.is_empty()) {
        println!("Tags: {}", tags.join(", "));
    }

    Ok(())
}

fn prompt_new_password() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let password = UserPrompt::visible_password("Password to store: ")?;
    Password::length_check(password.as_str(), MIN_ACCOUNT_PASSWORD_LENGTH)?;

    let confirmation = UserPrompt::password("Confirm password: ")?;
    Password::match_check(password.as_str(), confirmation.as_str())?;

    Ok(password)
}
