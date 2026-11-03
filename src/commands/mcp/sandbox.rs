use crate::{core::accounts::Accounts, mcp::config::McpConfig};

pub fn execute(state: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = McpConfig::load()?;

    let Some(raw_state) = state else {
        println!(
            "MCP sandbox (agent isolation): {}",
            if config.sandbox { "on" } else { "off" }
        );
        return Ok(());
    };

    let enabled = match raw_state.trim().to_lowercase().as_str() {
        "on" | "true" | "1" | "enable" | "enabled" => true,
        "off" | "false" | "0" | "disable" | "disabled" => false,
        _ => return Err("Invalid sandbox state. Use 'on' or 'off'.".into()),
    };

    config.sandbox = enabled;
    if enabled && config.active_agent_account.is_none() {
        let existing = Accounts::list_agents()?;
        if let Some(first) = existing.first() {
            config.active_agent_account = Some(first.clone());
        }
    }

    config.save()?;
    println!(
        "MCP sandbox (agent isolation) set to {}",
        if enabled { "on" } else { "off" }
    );

    Ok(())
}
