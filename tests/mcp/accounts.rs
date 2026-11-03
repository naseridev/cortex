use cortex::mcp::accounts::McpAccounts;
use cortex::mcp::config::{McpConfig, McpPermission};
use serde_json::json;

#[test]
fn status_reports_active_configuration_and_flags() -> Result<(), String> {
    let config = McpConfig {
        permission: "101".to_string(),
        sandbox: true,
        active_agent_account: Some("claude-agent".to_string()),
    };
    let perm = McpPermission::parse(&config.permission)?;
    let output = McpAccounts::status(&config, perm)?;
    let parsed: serde_json::Value = serde_json::from_str(&output).map_err(|e| e.to_string())?;

    assert_eq!(parsed["permission"], "101");
    assert_eq!(parsed["can_create_account"], true);
    assert_eq!(parsed["can_write"], false);
    assert_eq!(parsed["can_read"], true);
    assert_eq!(parsed["sandbox"], true);
    assert_eq!(parsed["active_agent_account"], "claude-agent");
    Ok(())
}

#[test]
fn listing_is_refused_without_read_permission() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = McpAccounts::list(&config, perm).expect_err("read must be denied");
    assert!(error.contains("Read access denied"));
    Ok(())
}

#[test]
fn account_creation_is_refused_without_account_permission() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("011")?;
    let error = McpAccounts::create(&config, perm, &json!({ "name": "agent" }))
        .expect_err("creation must be denied");
    assert!(error.contains("Account creation denied"));
    Ok(())
}

#[test]
fn account_creation_requires_a_name_before_touching_storage() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = McpAccounts::create(&config, perm, &json!({})).expect_err("name is required");
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}

#[test]
fn account_creation_rejects_reserved_names() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = McpAccounts::create(&config, perm, &json!({ "name": "__system" }))
        .expect_err("reserved name must be rejected");
    assert_eq!(error, "Invalid account name");
    Ok(())
}

#[test]
fn switching_is_refused_when_every_capability_is_off() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("000")?;
    let error = McpAccounts::switch(&config, perm, &json!({ "name": "agent" }))
        .expect_err("switch must be denied");
    assert_eq!(error, "Access denied by current MCP permission.");
    Ok(())
}

#[test]
fn switching_requires_a_name_when_permitted() -> Result<(), String> {
    let config = McpConfig::default();
    let perm = McpPermission::parse("001")?;
    let error = McpAccounts::switch(&config, perm, &json!({ "name": "  " }))
        .expect_err("blank name is missing");
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}
