use cortex::mcp::config::{McpConfig, McpPermission};
use cortex::mcp::entries::McpEntries;
use serde_json::json;

fn perm(raw: &str) -> Result<McpPermission, String> {
    McpPermission::parse(raw)
}

#[test]
fn listing_and_fetching_are_refused_without_read_permission() -> Result<(), String> {
    let config = McpConfig::default();
    let no_read = perm("110")?;

    let list_error = McpEntries::list(&config, no_read, &json!({})).expect_err("list denied");
    assert!(list_error.contains("Read access denied"));

    let get_error =
        McpEntries::get(&config, no_read, &json!({ "name": "bank" })).expect_err("get denied");
    assert!(get_error.contains("Read access denied"));
    Ok(())
}

#[test]
fn search_requires_read_permission_and_a_pattern() -> Result<(), String> {
    let config = McpConfig::default();

    let denied = McpEntries::search(&config, perm("010")?, &json!({ "pattern": "bank" }))
        .expect_err("search denied");
    assert!(denied.contains("Read access denied"));

    let missing =
        McpEntries::search(&config, perm("001")?, &json!({})).expect_err("pattern is required");
    assert_eq!(missing, "Missing required parameter: 'pattern'");
    Ok(())
}

#[test]
fn get_requires_a_name_once_read_is_allowed() -> Result<(), String> {
    let config = McpConfig::default();
    let error = McpEntries::get(&config, perm("001")?, &json!({})).expect_err("name is required");
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}

#[test]
fn mutations_are_refused_without_write_permission() -> Result<(), String> {
    let config = McpConfig::default();
    let read_only = perm("101")?;

    let create = McpEntries::create(&config, read_only, &json!({ "name": "bank" }))
        .expect_err("create denied");
    assert!(create.contains("Write/delete access denied"));

    let edit =
        McpEntries::edit(&config, read_only, &json!({ "name": "bank" })).expect_err("edit denied");
    assert!(edit.contains("Write/delete access denied"));

    let delete = McpEntries::delete(&config, read_only, &json!({ "name": "bank" }))
        .expect_err("delete denied");
    assert!(delete.contains("Write/delete access denied"));
    Ok(())
}

#[test]
fn create_rejects_reserved_names_once_write_is_allowed() -> Result<(), String> {
    let config = McpConfig::default();
    let error = McpEntries::create(&config, perm("010")?, &json!({ "name": "__config__" }))
        .expect_err("reserved name must be rejected");
    assert_eq!(error, "Invalid account name");
    Ok(())
}

#[test]
fn edit_and_delete_refuse_reserved_entries() -> Result<(), String> {
    let config = McpConfig::default();
    let write_only = perm("010")?;

    let edit = McpEntries::edit(&config, write_only, &json!({ "name": "__config__" }))
        .expect_err("reserved edit must be rejected");
    assert_eq!(edit, "Cannot edit system or empty entries");

    let delete = McpEntries::delete(&config, write_only, &json!({ "name": "__config__" }))
        .expect_err("reserved delete must be rejected");
    assert_eq!(delete, "Cannot delete system or empty entries");
    Ok(())
}

#[test]
fn delete_requires_a_name_once_write_is_allowed() -> Result<(), String> {
    let config = McpConfig::default();
    let error = McpEntries::delete(&config, perm("010")?, &json!({ "name": "   " }))
        .expect_err("blank name is missing");
    assert_eq!(error, "Missing required parameter: 'name'");
    Ok(())
}
