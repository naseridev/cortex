use crate::cloud::config::CloudConfig;

pub fn execute(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Remote name cannot be empty.".into());
    }

    let mut config = CloudConfig::load()?;
    config.set_default(trimmed)?;

    println!("Default cloud remote set to '{trimmed}'.");
    Ok(())
}
