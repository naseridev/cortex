use cortex::mcp::{
    accounts::McpAccounts,
    config::{McpConfig, McpPermission},
    guard::McpGuard,
    tools::McpTools,
};
use serde_json::json;

#[test]
fn permission_parser_validates_all_binary_combinations() -> Result<(), String> {
    let cases = [
        ("000", false, false, false, true),
        ("001", false, false, true, false),
        ("010", false, true, false, false),
        ("011", false, true, true, false),
        ("100", true, false, false, false),
        ("101", true, false, true, false),
        ("110", true, true, false, false),
        ("111", true, true, true, false),
    ];

    for (raw, acc, write, read, disabled) in cases {
        let perm = McpPermission::parse(raw)?;
        assert_eq!(perm.can_account(), acc);
        assert_eq!(perm.can_write(), write);
        assert_eq!(perm.can_read(), read);
        assert_eq!(perm.is_disabled(), disabled);
        assert_eq!(perm.as_str(), raw);
    }

    assert!(McpPermission::parse("").is_err());
    assert!(McpPermission::parse("01").is_err());
    assert!(McpPermission::parse("0110").is_err());
    assert!(McpPermission::parse("002").is_err());
    assert!(McpPermission::parse("abc").is_err());
    Ok(())
}

#[test]
fn guard_enforces_individual_permission_digits() -> Result<(), String> {
    let read_only = McpPermission::parse("001")?;
    assert!(McpGuard::require_read(read_only).is_ok());
    assert!(McpGuard::require_write(read_only).is_err());
    assert!(McpGuard::require_account(read_only).is_err());

    let write_only = McpPermission::parse("010")?;
    assert!(McpGuard::require_read(write_only).is_err());
    assert!(McpGuard::require_write(write_only).is_ok());
    assert!(McpGuard::require_account(write_only).is_err());

    let account_only = McpPermission::parse("100")?;
    assert!(McpGuard::require_read(account_only).is_err());
    assert!(McpGuard::require_write(account_only).is_err());
    assert!(McpGuard::require_account(account_only).is_ok());
    Ok(())
}

#[test]
fn guard_extracts_and_validates_tags_from_json_args() -> Result<(), String> {
    let from_array = json!({ "tags": ["Work", "finance", "work"] });
    assert_eq!(
        McpGuard::extract_tags(&from_array)?,
        Some(vec!["finance".to_string(), "work".to_string()])
    );

    let from_string = json!({ "tags": "alpha, beta, ALPHA" });
    assert_eq!(
        McpGuard::extract_tags(&from_string)?,
        Some(vec!["alpha".to_string(), "beta".to_string()])
    );

    let missing = json!({});
    assert_eq!(McpGuard::extract_tags(&missing)?, None);

    let invalid = json!({ "tags": 12345 });
    assert!(McpGuard::extract_tags(&invalid).is_err());
    Ok(())
}

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
fn unknown_tool_returns_structured_mcp_error() {
    let response = McpTools::dispatch(&json!({
        "name": "nonexistent_tool",
        "arguments": {}
    }));
    assert_eq!(response["isError"], true);
}