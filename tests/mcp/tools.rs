use cortex::mcp::tools::McpTools;
use serde_json::json;

#[test]
fn unknown_tool_returns_structured_mcp_error() {
    let response = McpTools::dispatch(&json!({
        "name": "nonexistent_tool",
        "arguments": {}
    }));
    assert_eq!(response["isError"], true);
    assert!(response["content"][0]["text"].is_string());
}
