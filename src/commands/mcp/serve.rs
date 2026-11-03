use crate::mcp::server::McpServer;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    McpServer::serve()
}
