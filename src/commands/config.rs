use crate::core::config::Config;

pub struct ConfigCmd;

impl ConfigCmd {
    pub fn show() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::load()?;
        println!("\nCurrent Configuration:");
        println!(
            "  Session timeout: {} seconds ({} minutes)",
            config.session_timeout_seconds,
            config.session_timeout_seconds / 60
        );
        println!(
            "  Hardware binding: {}",
            if config.hardware_binding_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        Ok(())
    }

    pub fn set_timeout(seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
        if seconds < 60 {
            return Err("Session timeout must be at least 60 seconds (1 minute)".into());
        }

        if seconds > 86400 {
            return Err("Session timeout cannot exceed 86400 seconds (24 hours)".into());
        }

        let mut config = Config::load()?;
        config.session_timeout_seconds = seconds;
        config.save()?;

        println!(
            "Session timeout set to {} seconds ({} minutes)",
            seconds,
            seconds / 60
        );
        Ok(())
    }

    pub fn set_hardware_binding(enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Config::load()?;
        config.hardware_binding_enabled = enabled;
        config.save()?;

        println!(
            "Hardware binding {}",
            if enabled { "enabled" } else { "disabled" }
        );

        if enabled {
            println!("\nNote: Database will be bound to this machine's CPU.");
            println!("You won't be able to access it from another machine.");
            println!("Use 'cortex export' to create portable backups.");
        }

        Ok(())
    }
}
