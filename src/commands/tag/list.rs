use crate::modules::gateway::Gateway;
use std::collections::HashMap;

pub fn execute() -> Result<(), Box<dyn std::error::Error>> {
    let (storage, crypto) = Gateway::login_with_session()?;
    let mut tag_counts: HashMap<String, usize> = HashMap::new();

    for (name, entry) in storage.list_entries()? {
        let tags = match crypto.decrypt_tags(&name, &entry) {
            Ok(tags) => tags,
            Err(error) => {
                eprintln!("Warning: skipping tags for '{name}': {error}");
                continue;
            }
        };

        for tag in tags {
            *tag_counts.entry(tag).or_insert(0) += 1;
        }
    }

    if tag_counts.is_empty() {
        println!("No tags found");
        return Ok(());
    }

    let mut sorted_tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
    sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    println!("\nTags:");
    for (tag, count) in sorted_tags {
        println!("  {tag} ({count})");
    }

    Ok(())
}
