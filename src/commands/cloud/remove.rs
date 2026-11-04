use crate::{cloud::config::CloudConfig, modules::security::Security};

pub fn execute(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Remote name cannot be empty.".into());
    }

    let mut config = CloudConfig::load()?;
    if !config.remotes.contains_key(trimmed) {
        return Err(format!("Cloud remote '{trimmed}' not found.").into());
    }

    Security::confirmation(&format!(
        "This will remove cloud remote '{trimmed}' and delete its stored credentials."
    ))?;

    config.remove_remote(trimmed)?;
    println!("Removed cloud remote '{trimmed}'.");
    Ok(())
}
