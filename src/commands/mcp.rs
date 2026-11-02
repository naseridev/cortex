use crate::{
    core::accounts::Accounts,
    mcp::{
        config::{McpConfig, McpPermission},
        server::McpServer,
    },
};
use serde_json::json;

pub struct Mcp;

impl Mcp {
    pub fn init() -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn permission(mode: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = McpConfig::load()?;

        let Some(raw_mode) = mode else {
            println!(
                "Current MCP permission: {} ({})",
                config.permission,
                config.describe_permission()?
            );
            return Ok(());
        };

        let parsed = McpPermission::parse(&raw_mode)?;
        config.permission = parsed.as_str().to_string();
        config.save()?;

        println!(
            "MCP permission set to {} ({})",
            config.permission,
            config.describe_permission()?
        );

        if parsed.is_disabled() {
            println!("MCP service is now locked (000). AI models have no access.");
        }

        Ok(())
    }

    pub fn sandbox(state: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn status() -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn remove(purge_accounts: bool) -> Result<(), Box<dyn std::error::Error>> {
        McpConfig::remove()?;

        if purge_accounts {
            let agent_accounts = Accounts::list_agents()?;
            for name in &agent_accounts {
                let _ = Accounts::delete(name);
            }
            println!(
                "MCP configuration removed and {} agent account(s) deleted.",
                agent_accounts.len()
            );
        } else {
            println!("MCP configuration removed. Existing agent accounts were kept.");
        }

        Ok(())
    }

    pub fn serve() -> Result<(), Box<dyn std::error::Error>> {
        McpServer::serve()
    }
}
