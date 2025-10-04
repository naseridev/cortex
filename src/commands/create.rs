use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, password::Password, validation::Validation},
    ui::prompt::UserPrompt,
};

const MIN_ACCOUNT_PASSWORD_LENGTH: usize = 4;

pub struct Create;

impl Create {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        Validation::account_exists_probe(
            &storage,
            &name,
            false,
            "Account '{}' already exists. Use 'edit' to update or choose a different name.",
        )?;

        let password = UserPrompt::text("Password to store: ")?;
        Password::length_check(&password, MIN_ACCOUNT_PASSWORD_LENGTH)?;

        let confirm_password = UserPrompt::text("Confirm password: ")?;
        Password::match_check(password.as_str(), confirm_password.as_str())?;

        let description_input = UserPrompt::text("Description (optional): ")?;
        Password::in_desc_check(password.as_str(), &description_input)?;

        let description = if description_input.is_empty() {
            None
        } else {
            Some(description_input.as_str())
        };

        let entry = crypto.create_entry(&SecureString::new(password).as_bytes(), description)?;

        if storage.create_password(&name, &entry)? {
            println!("Created '{}'.", name);
        }

        Ok(())
    }
}
