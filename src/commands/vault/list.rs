use crate::core::gateway::Gateway;
use crate::core::validation::Validation;

pub fn execute(show_tags: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login_with_session()?;
    let mut entries = Vec::new();

    for (name, entry) in storage.list_entries()? {
        let description = match crypto.decrypt_description(&name, &entry) {
            Ok(description) => description,
            Err(error) => {
                eprintln!("Warning: skipping entry '{name}': {error}");
                continue;
            }
        };

        let tags = if show_tags {
            match crypto.decrypt_tags(&name, &entry) {
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
            println!("Entry: {}", Validation::printable(&name));

            if let Some(desc) = &description {
                println!("Description: {}", Validation::printable(desc));
            }

            if show_tags && !tags.is_empty() {
                println!("Tags: {}", tags.join(", "));
            }
        }
    }

    Ok(())
}
