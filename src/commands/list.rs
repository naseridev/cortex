use crate::modules::gateway::Gateway;

pub struct List;

impl List {
    pub fn new(_: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let mut entries = Vec::new();

        for (name, entry) in storage.list_entries()? {
            let description = crypto.decrypt_description(&entry)?;
            let tags = crypto.decrypt_tags(&entry)?;
            entries.push((name, description, tags));
        }

        if entries.is_empty() {
            println!("No entries");
        } else {
            for (name, description, tags) in entries {
                println!();
                println!("Entry: {}", name);
                if let Some(desc) = &description {
                    println!("Description: {}", desc);
                }
                if !tags.is_empty() {
                    println!("Tags: {}", tags.join(", "));
                }
            }
        }

        Ok(())
    }
}
