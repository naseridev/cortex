use crate::{
    core::{
        config::Config, crypto::Crypto, password::Password, storage::Storage,
        validation::Validation,
    },
    modules::{gateway::Gateway, security::Security, session::Session},
    ui::prompt::UserPrompt,
};

pub struct Account;

impl Account {
    pub fn create(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let account_name = Self::resolve_name(name, "Account name: ")?;
        Validation::check_account_name(&account_name)?;

        if Storage::account_exists(&account_name)? {
            return Err(format!(
                "Account '{account_name}' already exists. Choose a different name."
            )
            .into());
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

        Storage::register_account(&account_name)?;
        Config::clear_cache();

        if let Err(error) = Session::save_session(crypto.key()) {
            eprintln!("Warning: session could not be stored: {error}");
        }

        println!("Initialized account '{account_name}'.");
        println!("\nIMPORTANT: Store your master password safely!");
        println!("There is NO way to recover it if lost.");

        Ok(())
    }

    pub fn list() -> Result<(), Box<dyn std::error::Error>> {
        let (accounts, active) = Storage::list_accounts()?;

        if accounts.is_empty() {
            println!("No accounts found. Create one with 'account create'.");
            return Ok(());
        }

        println!("\nAccounts:");
        for name in accounts {
            let printable = Validation::printable(&name);
            if active.as_deref() == Some(name.as_str()) {
                println!("  * {printable} (active)");
            } else {
                println!("    {printable}");
            }
        }

        Ok(())
    }

    pub fn edit(
        name: Option<String>,
        new_name: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (accounts, _) = Storage::list_accounts()?;
        if accounts.is_empty() {
            return Err("No accounts found. Create one with 'account create'.".into());
        }

        let current_name = Self::resolve_name(name, "Account name: ")?;
        Validation::check_account_name(&current_name)?;

        if !Storage::account_exists(&current_name)? {
            return Err(format!("Account '{current_name}' not found.").into());
        }

        let (storage, _) = Gateway::login_account(&current_name)?;
        drop(storage);

        let updated_name = Self::resolve_name(new_name, "New account name: ")?;
        Validation::check_account_name(&updated_name)?;

        if updated_name == current_name {
            println!("No changes made to '{current_name}'.");
            return Ok(());
        }

        if Storage::account_exists(&updated_name)? {
            return Err(format!(
                "Account '{updated_name}' already exists. Choose a different name."
            )
            .into());
        }

        Storage::rename_account(&current_name, &updated_name)?;
        println!("Renamed account '{current_name}' to '{updated_name}'.");

        Ok(())
    }

    pub fn delete(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let (accounts, _) = Storage::list_accounts()?;
        if accounts.is_empty() {
            return Err("No accounts found. Create one with 'account create'.".into());
        }

        let account_name = Self::resolve_name(name, "Account name: ")?;
        Validation::check_account_name(&account_name)?;

        if !Storage::account_exists(&account_name)? {
            return Err(format!("Account '{account_name}' not found.").into());
        }

        let (storage, _) = Gateway::login_account_for_recovery(&account_name)?;
        drop(storage);

        let warning_message = format!(
            "This will permanently delete account '{account_name}' and all its stored passwords!"
        );
        Security::confirmation(&warning_message)?;

        let was_active = Storage::delete_account(&account_name)?;
        if was_active {
            Session::clear_session()?;
            Config::clear_cache();
        }

        println!("Deleted account '{account_name}'.");
        Ok(())
    }

    pub fn switch(name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let (accounts, _) = Storage::list_accounts()?;
        if accounts.is_empty() {
            return Err("No accounts found. Create one with 'account create'.".into());
        }

        let account_name = Self::resolve_name(name, "Account name: ")?;
        Validation::check_account_name(&account_name)?;

        if !Storage::account_exists(&account_name)? {
            return Err(format!("Account '{account_name}' not found.").into());
        }

        if Storage::active_account()?.as_deref() == Some(account_name.as_str()) {
            println!("Account '{account_name}' is already active.");
            return Ok(());
        }

        Storage::switch_account(&account_name)?;
        Session::clear_session()?;
        Config::clear_cache();

        println!("Switched to account '{account_name}'.");
        Ok(())
    }

    fn resolve_name(
        provided: Option<String>,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match provided {
            Some(name) => Ok(name.trim().to_string()),
            None => UserPrompt::text(prompt),
        }
    }
}
