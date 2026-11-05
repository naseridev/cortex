use crate::core::{accounts::Accounts, validation::Validation};

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let (accounts, active) = Accounts::list()?;

    if accounts.is_empty() {
        println!("{}", crate::core::accounts::NO_ACCOUNTS);
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
