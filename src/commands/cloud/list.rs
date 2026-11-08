use crate::{cloud::config::CloudConfig, domain::validation::Validation};

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let config = CloudConfig::load()?;

    if config.remotes.is_empty() {
        println!("No cloud remotes configured. Add one with 'cortex cloud add'.");
        return Ok(());
    }

    println!("\nCloud Remotes:");
    for (name, remote) in &config.remotes {
        let printable_name = Validation::printable(name);
        let summary = Validation::printable(&remote.settings.summary());
        let is_default = config.active_remote.as_deref() == Some(name.as_str());

        if is_default {
            println!("  * {printable_name} -> {summary} (default)");
        } else {
            println!("    {printable_name} -> {summary}");
        }
    }

    Ok(())
}
