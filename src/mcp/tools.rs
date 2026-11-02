use crate::mcp::{
    accounts::McpAccounts,
    config::{McpConfig, McpPermission},
    entries::McpEntries,
};
use serde_json::{Value, json};

pub struct McpTools;

impl McpTools {
    #[must_use]
    pub fn dispatch(params: &Value) -> Value {
        let config = match McpConfig::load() {
            Ok(cfg) => cfg,
            Err(error) => return Self::tool_error(&format!("Failed to load MCP config: {error}")),
        };

        let perm = match McpPermission::parse(&config.permission) {
            Ok(p) => p,
            Err(error) => return Self::tool_error(&error),
        };

        if perm.is_disabled() {
            return Self::tool_error(
                "MCP service is currently disabled by user permission (000). Inform the user that Cortex MCP is in locked/disabled state (permission 000) and ask them to run 'cortex mcp permission <mode>' (e.g., 'cortex mcp permission 111') if they want to grant access.",
            );
        }

        let tool_name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let outcome = match tool_name {
            "vault_status" => McpAccounts::status(&config, perm),
            "list_accounts" => McpAccounts::list(&config, perm),
            "create_account" => McpAccounts::create(&config, perm, &args),
            "switch_account" => McpAccounts::switch(&config, perm, &args),
            "list_entries" => McpEntries::list(&config, perm, &args),
            "get_password" => McpEntries::get(&config, perm, &args),
            "search_entries" => McpEntries::search(&config, perm, &args),
            "create_entry" => McpEntries::create(&config, perm, &args),
            "edit_entry" => McpEntries::edit(&config, perm, &args),
            "delete_entry" => McpEntries::delete(&config, perm, &args),
            _ => Err(format!("Unknown tool: {tool_name}")),
        };

        match outcome {
            Ok(text) => Self::tool_success(&text),
            Err(message) => Self::tool_error(&message),
        }
    }

    fn tool_success(text: &str) -> Value {
        json!({
            "content": [
                {
                    "type": "text",
                    "text": text
                }
            ],
            "isError": false
        })
    }

    fn tool_error(message: &str) -> Value {
        json!({
            "content": [
                {
                    "type": "text",
                    "text": message
                }
            ],
            "isError": true
        })
    }
}
