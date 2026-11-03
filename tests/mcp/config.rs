use cortex::mcp::config::{McpConfig, McpPermission};

use crate::common::{TestResult, failure};

#[test]
fn permission_parser_validates_all_binary_combinations() -> TestResult {
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
fn permission_parser_trims_surrounding_whitespace() -> TestResult {
    let perm = McpPermission::parse("  101\t ")?;
    assert_eq!(perm.as_str(), "101");
    Ok(())
}

#[test]
fn invalid_permission_error_explains_the_digit_layout() -> TestResult {
    let error = failure(McpPermission::parse("12"))?;
    assert!(error.contains("3-digit binary"));
    Ok(())
}

#[test]
fn default_config_grants_full_access_with_sandbox_enabled() {
    let config = McpConfig::default();
    assert_eq!(config.permission, "111");
    assert!(config.sandbox);
    assert!(config.active_agent_account.is_none());
}

#[test]
fn describe_permission_summarizes_each_capability() -> TestResult {
    let describe = |permission: &str| {
        McpConfig {
            permission: permission.to_string(),
            sandbox: false,
            active_agent_account: None,
        }
        .describe_permission()
    };

    assert_eq!(describe("000")?, "disabled");
    assert_eq!(describe("101")?, "Account: yes, Write: no, Read: yes");
    assert_eq!(describe("010")?, "Account: no, Write: yes, Read: no");
    assert!(describe("1x1").is_err());
    Ok(())
}
