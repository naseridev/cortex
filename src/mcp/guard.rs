use crate::{
    core::{accounts::Accounts, crypto::Crypto, storage::Storage, tags::TagValidator},
    mcp::config::{McpConfig, McpPermission},
    modules::gateway::Gateway,
};
use serde_json::Value;

pub struct McpGuard;

impl McpGuard {
    pub fn open_vault(
        config: &McpConfig,
        perm: McpPermission,
        args: &Value,
    ) -> Result<(String, Storage, Crypto), String> {
        let requested = args
            .get("account")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let target_account = if config.sandbox {
            if let Some(name) = requested {
                let is_agent = Accounts::is_agent(&name).map_err(|e| e.to_string())?;
                if !is_agent {
                    return Err(format!(
                        "Sandbox mode is enabled: access to non-agent account '{name}' is forbidden. Only [agent] accounts can be accessed."
                    ));
                }
                name
            } else {
                Self::resolve_sandbox_account(config, perm)?
            }
        } else if let Some(name) = requested {
            name
        } else if let Some(agent_acc) = &config.active_agent_account
            && Accounts::exists(agent_acc).unwrap_or(false)
        {
            agent_acc.clone()
        } else if let Some(human_acc) = Accounts::active().map_err(|e| e.to_string())? {
            human_acc
        } else if perm.can_account() {
            let mut cfg = config.clone();
            let created = cfg
                .ensure_default_agent_account()
                .map_err(|e| e.to_string())?;
            let _ = cfg.save();
            created
        } else {
            return Err(
                "No accounts found. Inform the user to create an account or enable MCP account creation permission."
                    .to_string(),
            );
        };

        let (storage, crypto) =
            Gateway::login_for_mcp(&target_account).map_err(|e| e.to_string())?;
        Ok((target_account, storage, crypto))
    }

    pub fn resolve_sandbox_account(
        config: &McpConfig,
        perm: McpPermission,
    ) -> Result<String, String> {
        if let Some(active) = &config.active_agent_account
            && Accounts::is_agent(active).unwrap_or(false)
        {
            return Ok(active.clone());
        }

        let existing = Accounts::list_agents().map_err(|e| e.to_string())?;
        if let Some(first) = existing.first() {
            let mut updated = config.clone();
            updated.active_agent_account = Some(first.clone());
            let _ = updated.save();
            return Ok(first.clone());
        }

        if !perm.can_account() {
            return Err(
                "Sandbox mode requires an [agent] account, but none exists and account creation permission (hundreds digit) is 0. Inform the user to run 'cortex mcp permission 111' or 'cortex mcp init'."
                    .to_string(),
            );
        }

        let mut updated = config.clone();
        let created = updated
            .ensure_default_agent_account()
            .map_err(|e| e.to_string())?;
        updated.save().map_err(|e| e.to_string())?;
        Ok(created)
    }

    pub fn extract_tags(args: &Value) -> Result<Option<Vec<String>>, String> {
        let Some(raw_tags) = args.get("tags") else {
            return Ok(None);
        };

        if let Some(text) = raw_tags.as_str() {
            if text.trim().is_empty() {
                return Ok(Some(Vec::new()));
            }
            return TagValidator::parse_and_validate(text)
                .map(Some)
                .map_err(|e| e.to_string());
        }

        if let Some(array) = raw_tags.as_array() {
            let collected: Vec<String> = array
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            let normalized = TagValidator::normalize(&collected);
            TagValidator::validate(&normalized).map_err(|e| e.to_string())?;
            return Ok(Some(normalized));
        }

        Err(
            "Invalid tags format: expected a comma-separated string or array of strings"
                .to_string(),
        )
    }

    pub fn required_str(args: &Value, key: &str) -> Result<String, String> {
        args.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("Missing required parameter: '{key}'"))
    }

    pub fn require_read(perm: McpPermission) -> Result<(), String> {
        if perm.can_read() {
            Ok(())
        } else {
            Err(format!(
                "Read access denied by current MCP permission ({}). The ones digit is 0. Inform the user they can enable read access with 'cortex mcp permission'.",
                perm.as_str()
            ))
        }
    }

    pub fn require_write(perm: McpPermission) -> Result<(), String> {
        if perm.can_write() {
            Ok(())
        } else {
            Err(format!(
                "Write/delete access denied by current MCP permission ({}). The tens digit is 0. Inform the user they can enable write access with 'cortex mcp permission'.",
                perm.as_str()
            ))
        }
    }

    pub fn require_account(perm: McpPermission) -> Result<(), String> {
        if perm.can_account() {
            Ok(())
        } else {
            Err(format!(
                "Account creation denied by current MCP permission ({}). The hundreds digit is 0. Inform the user they can enable account creation with 'cortex mcp permission'.",
                perm.as_str()
            ))
        }
    }
}
