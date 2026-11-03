use crate::mcp::config::McpConfig;
use serde_json::json;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = if McpConfig::is_initialized()? {
        McpConfig::load()?
    } else {
        McpConfig::default()
    };

    if config.sandbox {
        let agent_account = config.ensure_default_agent_account()?;
        config.active_agent_account = Some(agent_account);
    }

    config.save()?;

    let exe_path = std::env::current_exe()
        .map_or_else(|_| "cortex".to_string(), |path| path.display().to_string());

    let snippet = serde_json::to_string_pretty(&json!({
        "mcpServers": {
            "cortex": {
                "command": exe_path,
                "args": ["mcp", "serve"]
            }
        }
    }))?;

    println!("MCP server initialized.");
    println!(
        "Permission: {} ({})",
        config.permission,
        config.describe_permission()?
    );

    println!(
        "Sandbox (agent isolation): {}",
        if config.sandbox { "on" } else { "off" }
    );

    if let Some(account) = &config.active_agent_account {
        println!("Active agent account: {account} [agent]");
    }

    println!("\nAdd this to your MCP client configuration:\n\n{snippet}");

    Ok(())
}
