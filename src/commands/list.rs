use crate::modules::gateway::Gateway;

pub struct List;

impl List {
    pub fn new() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let mut entries = Vec::new();

        for (name, entry) in storage.list_entries()? {
            let description = crypto.decrypt_description(&entry)?;
            entries.push((name, description));
        }

        if entries.is_empty() {
            println!("No entries");
        } else {
            for (name, description) in entries {
                println!();
                println!("Entry: {}", name);
                if let Some(desc) = &description {
                    println!("Description: {}", desc);
                }
            }
        }

        Ok(())
    }
}
