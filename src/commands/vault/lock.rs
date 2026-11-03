use crate::modules::session::Session;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    Session::clear_session()?;
    println!("Session cleared. You will need to authenticate again.");
    Ok(())
}
