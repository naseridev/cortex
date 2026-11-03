use cortex::mcp::accounts::McpAccounts;
use cortex::mcp::config::{McpConfig, McpPermission};
use serde_json::json;

use crate::common::{TestResult, failure};

#[test]
fn status_reports_active_configuration_and_flags() -> TestResult {
    let config = McpConfig {
        permission: "101".to_string(),
        sandbox: true,
        active_agent_account: Some("claude-agent".to_string()),
    };
    let perm = McpPermission::parse(&config.permission)?;
    let output = McpAccounts::status(&config, perm)?;
    let parsed: serde_json::Value = serde_json::from_str(&output)?;

    assert_eq!(parsed["permission"], "101");
    assert_eq!(parsed["can_create_account"], true);
    assert_eq!(parsed["can_write"], false);
    assert_eq!(parsed["can_read"], true);
    assert_eq!(parsed["sandbox"], true);
    assert_eq!(parsed["active_agent_account"], "claude-agent");
    Ok(())
}

#[test]
fn listing_is_refused_without_read_permission() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = failure(McpAccounts::list(&config, perm))?;
    assert!(error.contains("Read access denied"));
    Ok(())
}

#[test]
fn account_creation_is_refused_without_account_permission() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("011")?;
    let error = failure(McpAccounts::create(
        &config,
        perm,
        &json!({ "name": "agent" }),
    ))?;
    assert!(error.contains("Account creation denied"));
    Ok(())
}

#[test]
fn account_creation_requires_a_name_before_touching_storage() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = failure(McpAccounts::create(&config, perm, &json!({})))?;
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}

#[test]
fn account_creation_rejects_reserved_names() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("100")?;
    let error = failure(McpAccounts::create(
        &config,
        perm,
        &json!({ "name": "__system" }),
    ))?;
    assert_eq!(error, "Invalid account name");
    Ok(())
}

#[test]
fn switching_is_refused_when_every_capability_is_off() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("000")?;
    let error = failure(McpAccounts::switch(
        &config,
        perm,
        &json!({ "name": "agent" }),
    ))?;
    assert_eq!(error, "Access denied by current MCP permission.");
    Ok(())
}

#[test]
fn switching_requires_a_name_when_permitted() -> TestResult {
    let config = McpConfig::default();
    let perm = McpPermission::parse("001")?;
    let error = failure(McpAccounts::switch(&config, perm, &json!({ "name": "  " })))?;
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}
