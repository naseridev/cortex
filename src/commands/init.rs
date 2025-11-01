use crate::{
    core::{crypto::Crypto, storage::Storage},
    modules::{password::Password, validation::Validation},
    ui::prompt::UserPrompt,
};

pub struct Init;

impl Init {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        Validation::storage_probe(
            false,
            "Database already exists. Use a different path or remove existing database.",
        )?;

        let master_password = UserPrompt::password("Master password: ")?;

        if let Err(msg) = Password::security_check(master_password.as_str()) {
            return Err(format!("{}", msg).into());
        }

        let confirm_password = UserPrompt::password("Confirm password: ")?;
        Password::match_check(master_password.as_str(), confirm_password.as_str())?;

        let salt = Crypto::generate_salt();

        let verification_data = Crypto::create_verification_data(&master_password, &salt);

        Storage::new()?.init_db(&verification_data, &salt)?;

        println!("Initialized.");
        println!("\nIMPORTANT: Store your master password safely!");
        println!("There is NO way to recover it if lost.");

        Ok(())
    }
}
