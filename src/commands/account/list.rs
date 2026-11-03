use crate::core::{accounts::Accounts, validation::Validation};

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let (accounts, active) = Accounts::list()?;

    if accounts.is_empty() {
        println!("No accounts found. Create one with 'account create'.");
        return Ok(());
    }

    println!("\nAccounts:");
    for name in accounts {
        let printable = Validation::printable(&name);
        let is_agent = Accounts::is_agent(&name)?;
        let tag = if is_agent { " [agent]" } else { "" };

        if active.as_deref() == Some(name.as_str()) {
            println!("  * {printable}{tag} (active)");
        } else {
            println!("    {printable}{tag}");
        }
    }

    Ok(())
}
