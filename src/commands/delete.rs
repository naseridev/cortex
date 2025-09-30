use crate::modules::gateway::Gateway;

pub struct Delete;

impl Delete {
    pub fn new(name: String) -> Result<(), Box<dyn std::error::Error>> {
        let storage = Gateway::login_storage_only()?;

        if storage.delete_password(&name)? {
            println!("Deleted '{}'.", name);
        } else {
            println!("Not found: {}", name);
        }

        Ok(())
    }
}
