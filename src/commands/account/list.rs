use crate::{
    domain::validation::Validation,
    storage::accounts::{Accounts, NO_ACCOUNTS},
};

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let (accounts, active) = Accounts::list()?;

    if accounts.is_empty() {
        println!("{NO_ACCOUNTS}");
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
