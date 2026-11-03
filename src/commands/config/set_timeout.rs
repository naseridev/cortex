use super::describe_timeout;
use crate::{core::config::Config, modules::gateway::Gateway};

const MIN_TIMEOUT_SECONDS: u64 = 60;
const MAX_TIMEOUT_SECONDS: u64 = 86_400;

pub fn execute(seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    if seconds < MIN_TIMEOUT_SECONDS {
        return Err("Session timeout must be at least 60 seconds (1 minute)".into());
    }

    if seconds > MAX_TIMEOUT_SECONDS {
        return Err("Session timeout cannot exceed 86400 seconds (24 hours)".into());
    }

    let storage = Gateway::login_storage_only()?;
    let mut config = Config::load_from_db(&storage)?;

    config.session_timeout_seconds = seconds;
    config.save_to_db(&storage)?;

    println!("Session timeout set to {}", describe_timeout(seconds));
    Ok(())
}
