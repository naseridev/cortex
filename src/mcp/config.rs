use crate::core::{accounts::Accounts, storage::Storage, time::Time};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const MCP_CONFIG_FILE: &str = "mcp.bin";
const DEFAULT_AGENT_ACCOUNT: &str = "agent";
const FALLBACK_AGENT_ACCOUNT: &str = "cortex-agent";

#[derive(Serialize, Deserialize, Clone)]
pub struct McpConfig {
    pub permission: String,
    pub sandbox: bool,
    pub active_agent_account: Option<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            permission: "111".to_string(),
            sandbox: true,
            active_agent_account: None,
        }
    }
}

impl McpConfig {
    pub fn is_initialized() -> Result<bool, Box<dyn std::error::Error>> {
        Ok(Self::config_path()?.exists())
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let bytes =
            fs::read(&path).map_err(|error| format!("Failed to read MCP config: {error}"))?;
        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let mut config: Self = Storage::decode_value(&bytes)
            .map_err(|error| format!("Invalid MCP config data: {error}"))?;

        if McpPermission::parse(&config.permission).is_err() {
            config.permission = "000".to_string();
        }

        if let Some(active) = &config.active_agent_account
            && !Accounts::exists(active).unwrap_or(false)
        {
            config.active_agent_account = None;
        }

        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        McpPermission::parse(&self.permission)?;
        let path = Self::config_path()?;
        let bytes = Storage::encode_value(self)?;
        Accounts::write_atomic_file(&path, &bytes)
    }

    pub fn remove() -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("Failed to remove MCP config: {error}"))?;
        }
        Ok(())
    }

    pub fn describe_permission(&self) -> Result<String, Box<dyn std::error::Error>> {
        let perm = McpPermission::parse(&self.permission)?;

        if perm.is_disabled() {
            return Ok("disabled".to_string());
        }

        Ok(format!(
            "Account: {}, Write: {}, Read: {}",
            if perm.can_account() { "yes" } else { "no" },
            if perm.can_write() { "yes" } else { "no" },
            if perm.can_read() { "yes" } else { "no" }
        ))
    }

    pub fn ensure_default_agent_account(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(active) = &self.active_agent_account
            && Accounts::is_agent(active)?
        {
            return Ok(active.clone());
        }

        let existing = Accounts::list_agents()?;

        if let Some(first) = existing.first() {
            self.active_agent_account = Some(first.clone());
            return Ok(first.clone());
        }

        let candidate = if !Accounts::exists(DEFAULT_AGENT_ACCOUNT)? {
            DEFAULT_AGENT_ACCOUNT.to_string()
        } else if !Accounts::exists(FALLBACK_AGENT_ACCOUNT)? {
            FALLBACK_AGENT_ACCOUNT.to_string()
        } else {
            format!("agent-{}", Time::current_timestamp())
        };

        Accounts::create_agent(&candidate)?;

        self.active_agent_account = Some(candidate.clone());
        Ok(candidate)
    }

    fn config_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(Accounts::cortex_dir()?.join(MCP_CONFIG_FILE))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct McpPermission {
    account: bool,
    write: bool,
    read: bool,
}

impl McpPermission {
    pub fn parse(mode: &str) -> Result<Self, String> {
        let trimmed = mode.trim();
        let bytes = trimmed.as_bytes();

        if bytes.len() != 3 || !bytes.iter().all(|b| *b == b'0' || *b == b'1') {
            return Err(
                "Invalid permission format. Use a 3-digit binary value between 000 and 111 (hundreds: account create, tens: write/delete, ones: read)."
                    .to_string(),
            );
        }

        Ok(Self {
            account: bytes[0] == b'1',
            write: bytes[1] == b'1',
            read: bytes[2] == b'1',
        })
    }

    #[must_use]
    pub const fn can_account(self) -> bool {
        self.account
    }

    #[must_use]
    pub const fn can_write(self) -> bool {
        self.write
    }

    #[must_use]
    pub const fn can_read(self) -> bool {
        self.read
    }

    #[must_use]
    pub const fn is_disabled(self) -> bool {
        !self.account && !self.write && !self.read
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match (self.account, self.write, self.read) {
            (false, false, false) => "000",
            (false, false, true) => "001",
            (false, true, false) => "010",
            (false, true, true) => "011",
            (true, false, false) => "100",
            (true, false, true) => "101",
            (true, true, false) => "110",
            (true, true, true) => "111",
        }
    }
}
