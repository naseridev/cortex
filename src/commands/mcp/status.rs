use crate::{core::accounts::Accounts, mcp::config::McpConfig};

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let initialized = McpConfig::is_initialized()?;
    let config = McpConfig::load()?;
    let agent_accounts = Accounts::list_agents()?;

    println!("\nMCP Status:");
    println!("  Initialized: {}", if initialized { "yes" } else { "no" });
    println!(
        "  Permission: {} ({})",
        config.permission,
        config.describe_permission()?
    );

    println!(
        "  Sandbox (agent isolation): {}",
        if config.sandbox { "on" } else { "off" }
    );

    println!(
        "  Active agent account: {}",
        config.active_agent_account.as_deref().unwrap_or("none")
    );

    if agent_accounts.is_empty() {
        println!("  Agent accounts: none");
    } else {
        println!("  Agent accounts: {}", agent_accounts.join(", "));
    }

    Ok(())
}
