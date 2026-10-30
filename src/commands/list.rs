use crate::modules::gateway::Gateway;

pub struct List;

impl List {
    pub fn execute(show_tags: bool) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let mut entries = Vec::new();

        for (name, entry) in storage.list_entries()? {
            let description = match crypto.decrypt_description(&entry) {
                Ok(description) => description,
                Err(error) => {
                    eprintln!("Warning: skipping entry '{name}': {error}");
                    continue;
                }
            };
            let tags = if show_tags {
                match crypto.decrypt_tags(&entry) {
                    Ok(tags) => tags,
                    Err(error) => {
                        eprintln!("Warning: skipping entry '{name}': {error}");
                        continue;
                    }
                }
            } else {
                Vec::new()
            };
            entries.push((name, description, tags));
        }

        if entries.is_empty() {
            println!("No entries");
        } else {
            for (name, description, tags) in entries {
                println!();
                println!("Entry: {name}");
                if let Some(desc) = &description {
                    println!("Description: {desc}");
                }
                if show_tags && !tags.is_empty() {
                    println!("Tags: {}", tags.join(", "));
                }
            }
        }

        Ok(())
    }
}
