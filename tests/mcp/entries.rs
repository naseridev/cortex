use cortex::mcp::config::{McpConfig, McpPermission};
use cortex::mcp::entries::McpEntries;
use serde_json::json;

use crate::common::{TestResult, failure};

fn perm(raw: &str) -> Result<McpPermission, String> {
    McpPermission::parse(raw)
}

#[test]
fn listing_and_fetching_are_refused_without_read_permission() -> TestResult {
    let config = McpConfig::default();
    let no_read = perm("110")?;

    let list_error = failure(McpEntries::list(&config, no_read, &json!({})))?;
    assert!(list_error.contains("Read access denied"));

    let get_error = failure(McpEntries::get(
        &config,
        no_read,
        &json!({ "name": "bank" }),
    ))?;
    assert!(get_error.contains("Read access denied"));
    Ok(())
}

#[test]
fn search_requires_read_permission_and_a_pattern() -> TestResult {
    let config = McpConfig::default();

    let denied = failure(McpEntries::search(
        &config,
        perm("010")?,
        &json!({ "pattern": "bank" }),
    ))?;
    assert!(denied.contains("Read access denied"));

    let missing = failure(McpEntries::search(&config, perm("001")?, &json!({})))?;
    assert_eq!(missing, "Missing required parameter: 'pattern'");
    Ok(())
}

#[test]
fn get_requires_a_name_once_read_is_allowed() -> TestResult {
    let config = McpConfig::default();
    let error = failure(McpEntries::get(&config, perm("001")?, &json!({})))?;
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}

#[test]
fn mutations_are_refused_without_write_permission() -> TestResult {
    let config = McpConfig::default();
    let read_only = perm("101")?;

    let create = failure(McpEntries::create(
        &config,
        read_only,
        &json!({ "name": "bank" }),
    ))?;
    assert!(create.contains("Write/delete access denied"));

    let edit = failure(McpEntries::edit(
        &config,
        read_only,
        &json!({ "name": "bank" }),
    ))?;
    assert!(edit.contains("Write/delete access denied"));

    let delete = failure(McpEntries::delete(
        &config,
        read_only,
        &json!({ "name": "bank" }),
    ))?;
    assert!(delete.contains("Write/delete access denied"));
    Ok(())
}

#[test]
fn create_rejects_reserved_names_once_write_is_allowed() -> TestResult {
    let config = McpConfig::default();
    let error = failure(McpEntries::create(
        &config,
        perm("010")?,
        &json!({ "name": "__config__" }),
    ))?;
    assert_eq!(error, "Invalid account name");
    Ok(())
}

#[test]
fn edit_and_delete_refuse_reserved_entries() -> TestResult {
    let config = McpConfig::default();
    let write_only = perm("010")?;

    let edit = failure(McpEntries::edit(
        &config,
        write_only,
        &json!({ "name": "__config__" }),
    ))?;
    assert_eq!(edit, "Cannot edit system or empty entries");

    let delete = failure(McpEntries::delete(
        &config,
        write_only,
        &json!({ "name": "__config__" }),
    ))?;
    assert_eq!(delete, "Cannot delete system or empty entries");
    Ok(())
}

#[test]
fn delete_requires_a_name_once_write_is_allowed() -> TestResult {
    let config = McpConfig::default();
    let error = failure(McpEntries::delete(
        &config,
        perm("010")?,
        &json!({ "name": "   " }),
    ))?;
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}
