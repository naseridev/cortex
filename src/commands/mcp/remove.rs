use crate::{core::accounts::Accounts, mcp::config::McpConfig};

pub fn execute(purge_accounts: bool) -> Result<(), Box<dyn std::error::Error>> {
    McpConfig::remove()?;

    if purge_accounts {
        let agent_accounts = Accounts::list_agents()?;
        for name in &agent_accounts {
            let _ = Accounts::delete(name);
        }
        println!(
            "MCP configuration removed and {} agent account(s) deleted.",
            agent_accounts.len()
        );
    } else {
        println!("MCP configuration removed. Existing agent accounts were kept.");
    }

    Ok(())
}
