use crate::{
    core::{accounts::Accounts, validation::Validation},
    mcp::{
        config::{McpConfig, McpPermission},
        guard::McpGuard,
    },
};
use serde_json::{Value, json};

pub struct McpAccounts;

impl McpAccounts {
    pub fn status(config: &McpConfig, perm: McpPermission) -> Result<String, String> {
        let agent_accounts = Accounts::list_agents().map_err(|e| e.to_string())?;
        let payload = json!({
            "permission": perm.as_str(),
            "can_create_account": perm.can_account(),
            "can_write": perm.can_write(),
            "can_read": perm.can_read(),
            "sandbox": config.sandbox,
            "active_agent_account": config.active_agent_account,
            "agent_accounts": agent_accounts,
        });
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
    }

    pub fn list(config: &McpConfig, perm: McpPermission) -> Result<String, String> {
        McpGuard::require_read(perm)?;

        if config.sandbox {
            let accounts = Accounts::list_agents().map_err(|e| e.to_string())?;
            let payload = json!({
                "sandbox": true,
                "active_account": config.active_agent_account,
                "accounts": accounts.into_iter().map(|name| json!({
                    "name": name,
                    "tag": "agent"
                })).collect::<Vec<_>>()
            });
            return serde_json::to_string_pretty(&payload).map_err(|e| e.to_string());
        }

        let (accounts, human_active) = Accounts::list().map_err(|e| e.to_string())?;
        let mut list = Vec::with_capacity(accounts.len());
        for name in accounts {
            let is_agent = Accounts::is_agent(&name).map_err(|e| e.to_string())?;
            list.push(json!({
                "name": name,
                "tag": if is_agent { "agent" } else { "user" }
            }));
        }

        let payload = json!({
            "sandbox": false,
            "active_mcp_account": config.active_agent_account.as_ref().or(human_active.as_ref()),
            "accounts": list
        });
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
    }

    pub fn create(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_account(perm)?;

        let name = McpGuard::required_str(args, "name")?;
        Validation::check_account_name(&name)?;

        if Accounts::exists(&name).map_err(|e| e.to_string())? {
            return Err(format!("Account '{name}' already exists."));
        }

        Accounts::create_agent(&name).map_err(|e| e.to_string())?;

        let mut updated_config = config.clone();
        updated_config.active_agent_account = Some(name.clone());
        updated_config.save().map_err(|e| e.to_string())?;

        Ok(format!(
            "Created isolated agent account '{name}' [agent] and set it as the active MCP account."
        ))
    }

    pub fn switch(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        if !perm.can_account() && !perm.can_read() && !perm.can_write() {
            return Err("Access denied by current MCP permission.".to_string());
        }

        let name = McpGuard::required_str(args, "name")?;
        Validation::check_account_name(&name)?;

        if !Accounts::exists(&name).map_err(|e| e.to_string())? {
            return Err(format!("Account '{name}' not found."));
        }

        let is_agent = Accounts::is_agent(&name).map_err(|e| e.to_string())?;
        if config.sandbox && !is_agent {
            return Err(format!(
                "Sandbox mode is enabled: switching to non-agent account '{name}' is forbidden. Only [agent] accounts can be used."
            ));
        }

        let mut updated_config = config.clone();
        updated_config.active_agent_account = Some(name.clone());
        updated_config.save().map_err(|e| e.to_string())?;

        Ok(format!("Switched active MCP account to '{name}'."))
    }
}
