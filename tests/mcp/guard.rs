use cortex::mcp::config::McpPermission;
use cortex::mcp::guard::McpGuard;
use serde_json::json;

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
fn permission_denials_name_the_digit_and_the_current_mode() -> Result<(), String> {
    let none = McpPermission::parse("000")?;
    let read_error = McpGuard::require_read(none).expect_err("read must be denied");
    assert!(read_error.contains("000"));
    assert!(read_error.contains("ones digit"));

    let read_only = McpPermission::parse("001")?;
    let write_error = McpGuard::require_write(read_only).expect_err("write must be denied");
    assert!(write_error.contains("tens digit"));

    let write_only = McpPermission::parse("010")?;
    let account_error = McpGuard::require_account(write_only).expect_err("account must be denied");
    assert!(account_error.contains("hundreds digit"));
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
fn blank_tag_strings_clear_tags_instead_of_failing() -> Result<(), String> {
    assert_eq!(
        McpGuard::extract_tags(&json!({ "tags": "" }))?,
        Some(Vec::new())
    );
    assert_eq!(
        McpGuard::extract_tags(&json!({ "tags": "   " }))?,
        Some(Vec::new())
    );
    Ok(())
}

#[test]
fn invalid_tags_are_rejected_in_both_argument_forms() {
    assert!(McpGuard::extract_tags(&json!({ "tags": "bad tag" })).is_err());
    assert!(McpGuard::extract_tags(&json!({ "tags": ["bad@tag"] })).is_err());
}

#[test]
fn tag_arrays_longer_than_the_limit_are_rejected() {
    let too_many: Vec<String> = (0..21).map(|i| format!("t{i}")).collect();
    assert!(McpGuard::extract_tags(&json!({ "tags": too_many })).is_err());
}

#[test]
fn required_string_is_trimmed_and_must_be_present() -> Result<(), String> {
    assert_eq!(
        McpGuard::required_str(&json!({ "name": "  work  " }), "name")?,
        "work"
    );

    let missing = McpGuard::required_str(&json!({}), "name").expect_err("missing");
    assert_eq!(missing, "Missing required parameter: 'name'");

    assert!(McpGuard::required_str(&json!({ "name": "   " }), "name").is_err());
    assert!(McpGuard::required_str(&json!({ "name": 42 }), "name").is_err());
    Ok(())
}
