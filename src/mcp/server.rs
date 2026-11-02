use crate::mcp::tools::McpTools;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub struct McpServer;

impl McpServer {
    pub fn serve() -> Result<(), Box<dyn std::error::Error>> {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut stdout = io::stdout();

        while let Some(message) = Self::read_rpc_message(&mut reader)? {
            if message.trim().is_empty() {
                continue;
            }

            let parsed: Value = if let Ok(val) = serde_json::from_str(&message) {
                val
            } else {
                let err = Self::rpc_error(&Value::Null, -32700, "Parse error");
                Self::write_rpc_message(&mut stdout, &err)?;
                continue;
            };

            if let Some(response) = Self::handle_rpc_request(&parsed) {
                Self::write_rpc_message(&mut stdout, &response)?;
            }
        }

        Ok(())
    }

    fn read_rpc_message<R: BufRead>(reader: &mut R) -> Result<Option<String>, io::Error> {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;

        if bytes == 0 {
            return Ok(None);
        }

        if line.to_ascii_lowercase().starts_with("content-length:") {
            let len_str = line["content-length:".len()..].trim();
            let content_len: usize = len_str.parse().unwrap_or(0);

            loop {
                let mut header_line = String::new();
                let n = reader.read_line(&mut header_line)?;
                if n == 0 || header_line == "\r\n" || header_line == "\n" {
                    break;
                }
            }

            let mut buf = vec![0u8; content_len];
            reader.read_exact(&mut buf)?;

            let body = String::from_utf8_lossy(&buf).into_owned();
            return Ok(Some(body));
        }

        Ok(Some(line))
    }

    fn write_rpc_message<W: Write>(writer: &mut W, payload: &Value) -> Result<(), io::Error> {
        let serialized = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
        writeln!(writer, "{serialized}")?;
        writer.flush()
    }

    fn handle_rpc_request(request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "initialize" => {
                let client_version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION);

                let res = json!({
                    "protocolVersion": client_version,
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "cortex-mcp",
                        "version": "4.0.0"
                    }
                });

                Some(Self::rpc_result(id.as_ref().unwrap_or(&Value::Null), &res))
            }
            "notifications/initialized" | "notifications/cancelled" => None,
            "ping" => Some(Self::rpc_result(
                id.as_ref().unwrap_or(&Value::Null),
                &json!({}),
            )),
            "resources/list" => Some(Self::rpc_result(
                id.as_ref().unwrap_or(&Value::Null),
                &json!({ "resources": [] }),
            )),
            "resources/templates/list" => Some(Self::rpc_result(
                id.as_ref().unwrap_or(&Value::Null),
                &json!({ "resourceTemplates": [] }),
            )),
            "prompts/list" => Some(Self::rpc_result(
                id.as_ref().unwrap_or(&Value::Null),
                &json!({ "prompts": [] }),
            )),
            "tools/list" => Some(Self::rpc_result(
                id.as_ref().unwrap_or(&Value::Null),
                &json!({ "tools": Self::tool_definitions() }),
            )),
            "tools/call" => {
                let req_id = id.unwrap_or(Value::Null);
                let result = McpTools::dispatch(&params);
                Some(Self::rpc_result(&req_id, &result))
            }
            _ => id.map(|req_id| Self::rpc_error(&req_id, -32601, "Method not found")),
        }
    }

    fn rpc_result(id: &Value, result: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        })
    }

    fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    fn tool_definitions() -> Value {
        let mut tools = Self::account_tool_definitions();
        tools.extend(Self::entry_tool_definitions());
        Value::Array(tools)
    }

    fn account_tool_definitions() -> Vec<Value> {
        vec![
            json!({
                "name": "vault_status",
                "description": "Check Cortex MCP permission level, sandbox mode, and active agent account.",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "list_accounts",
                "description": "List accessible Cortex accounts and see which ones carry the [agent] system tag.",
                "inputSchema": { "type": "object", "properties": {} }
            }),
            json!({
                "name": "create_account",
                "description": "Create a new isolated [agent] account with an automatically managed master key (requires hundreds digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Name of the new agent account" }
                    },
                    "required": ["name"]
                }
            }),
            json!({
                "name": "switch_account",
                "description": "Switch the active MCP account without affecting the human user's CLI session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Account name to switch to" }
                    },
                    "required": ["name"]
                }
            }),
        ]
    }

    fn entry_tool_definitions() -> Vec<Value> {
        vec![
            json!({
                "name": "list_entries",
                "description": "List all stored password entry names, descriptions, and tags (requires ones digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": { "type": "string", "description": "Optional account name override" }
                    }
                }
            }),
            json!({
                "name": "get_password",
                "description": "Retrieve the plaintext password, description, and tags for an entry (requires ones digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Entry name" },
                        "account": { "type": "string", "description": "Optional account name override" }
                    },
                    "required": ["name"]
                }
            }),
            json!({
                "name": "search_entries",
                "description": "Search entries by regex pattern across names, descriptions, and tags (requires ones digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Regex search pattern" },
                        "ignore_case": { "type": "boolean", "description": "Case-insensitive matching (default: true)" },
                        "names_only": { "type": "boolean", "description": "Search only entry names" },
                        "account": { "type": "string", "description": "Optional account name override" }
                    },
                    "required": ["pattern"]
                }
            }),
            json!({
                "name": "create_entry",
                "description": "Create a new password entry. Generates a strong password automatically if password is omitted (requires tens digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Identifier for the password entry" },
                        "password": { "type": "string", "description": "Password to store (omit to auto-generate a strong password)" },
                        "length": { "type": "integer", "description": "Length for auto-generated password (default: 20)" },
                        "description": { "type": "string", "description": "Optional description" },
                        "tags": { "type": "array", "items": { "type": "string" }, "description": "Optional list of tags" },
                        "account": { "type": "string", "description": "Optional account name override" }
                    },
                    "required": ["name"]
                }
            }),
            json!({
                "name": "edit_entry",
                "description": "Update password, description, or tags of an existing entry (requires tens digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Entry name to update" },
                        "password": { "type": "string", "description": "New password (omit to keep current)" },
                        "description": { "type": "string", "description": "New description (omit to keep current)" },
                        "tags": { "type": "array", "items": { "type": "string" }, "description": "New list of tags (omit to keep current)" },
                        "account": { "type": "string", "description": "Optional account name override" }
                    },
                    "required": ["name"]
                }
            }),
            json!({
                "name": "delete_entry",
                "description": "Delete a password entry from the vault (requires tens digit = 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Entry name to delete" },
                        "account": { "type": "string", "description": "Optional account name override" }
                    },
                    "required": ["name"]
                }
            }),
        ]
    }
}
