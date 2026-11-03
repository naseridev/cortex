use super::resolve_name;
use crate::{
    core::{
        accounts::Accounts, config::Config, crypto::Crypto, password::Password, storage::Storage,
        validation::Validation,
    },
    modules::session::Session,
    ui::prompt::UserPrompt,
};

pub fn execute(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let account_name = resolve_name(name, "Account name: ")?;
    Validation::check_account_name(&account_name)?;

    if Accounts::exists(&account_name)? {
        return Err(
            format!("Account '{account_name}' already exists. Choose a different name.").into(),
        );
    }

    let master_password = UserPrompt::password("Master password: ")?;

    if let Err(msg) = Password::security_check(master_password.as_str()) {
        return Err(msg.into());
    }

    let confirm_password = UserPrompt::password("Confirm password: ")?;
    Password::match_check(master_password.as_str(), confirm_password.as_str())?;

    let (crypto, salt) = Crypto::create(&master_password)?;
    let storage = Storage::open_account(&account_name)?;
    storage.init_db(&crypto, &salt)?;
    drop(storage);

    Accounts::register(&account_name)?;
    Config::clear_cache();

    if let Err(error) = Session::save_session(crypto.key()) {
        eprintln!("Warning: session could not be stored: {error}");
    }

    println!("Initialized account '{account_name}'.");
    println!("\nIMPORTANT: Store your master password safely!");
    println!("There is NO way to recover it if lost.");

    Ok(())
}
