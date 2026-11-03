pub mod init;
pub mod permission;
pub mod remove;
pub mod sandbox;
pub mod serve;
pub mod status;

use crate::ui::cli::McpAction;

pub fn run(action: McpAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        McpAction::Init => init::execute(),
        McpAction::Serve => serve::execute(),
        McpAction::Permission { mode } => permission::execute(mode),
        McpAction::Sandbox { state } => sandbox::execute(state),
        McpAction::Status => status::execute(),
        McpAction::Remove { purge_accounts } => remove::execute(purge_accounts),
    }
}
