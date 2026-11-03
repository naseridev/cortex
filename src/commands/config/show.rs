use super::describe_timeout;
use crate::core::config::Config;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;

    println!("\nCurrent Configuration:");
    println!(
        "  Session timeout: {}",
        describe_timeout(config.session_timeout_seconds)
    );
    Ok(())
}
