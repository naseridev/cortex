use crate::mcp::config::{McpConfig, McpPermission};

pub fn execute(mode: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
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
