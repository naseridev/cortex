use crate::modules::{gateway::Gateway, tags::TagValidator};
use std::collections::HashMap;

pub struct Tag;

impl Tag {
    pub fn list() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let mut tag_counts: HashMap<String, usize> = HashMap::new();

        for (_, entry) in storage.list_entries()? {
            let tags = crypto.decrypt_tags(&entry)?;
            for tag in tags {
                *tag_counts.entry(tag).or_insert(0) += 1;
            }
        }

        if tag_counts.is_empty() {
            println!("No tags found");
            return Ok(());
        }

        let mut sorted_tags: Vec<_> = tag_counts.into_iter().collect();
        sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        println!("\nTags:");
        for (tag, count) in sorted_tags {
            println!("  {} ({})", tag, count);
        }

        Ok(())
    }

    pub fn add(name: String, tags: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Cannot modify system entries".into());
        }

        let normalized_tags = TagValidator::normalize(&tags);
        TagValidator::validate(&normalized_tags)?;

        let (storage, crypto) = Gateway::login()?;

        let entry = storage
            .get_password(&name)?
            .ok_or_else(|| format!("Entry '{}' not found", name))?;

        let mut existing_tags = crypto.decrypt_tags(&entry)?;
        let existing_set: std::collections::HashSet<String> =
            existing_tags.iter().map(|t| t.to_lowercase()).collect();

        let mut added_count = 0;
        for tag in normalized_tags {
            if !existing_set.contains(&tag.to_lowercase()) {
                existing_tags.push(tag);
                added_count += 1;
            }
        }

        if added_count == 0 {
            println!("No new tags added (all tags already exist)");
            return Ok(());
        }

        let normalized_final = TagValidator::normalize(&existing_tags);
        TagValidator::validate(&normalized_final)?;

        let password_data = crypto.decrypt_entry(&entry)?;
        let description = crypto.decrypt_description(&entry)?;

        let new_entry = crypto.create_entry(
            &password_data,
            description.as_deref(),
            Some(&normalized_final),
        )?;

        storage.edit_password(&name, &new_entry)?;
        println!("Added {} tag(s) to '{}'", added_count, name);

        Ok(())
    }

    pub fn remove(name: String, tags: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") {
            return Err("Cannot modify system entries".into());
        }

        let (storage, crypto) = Gateway::login()?;

        let entry = storage
            .get_password(&name)?
            .ok_or_else(|| format!("Entry '{}' not found", name))?;

        let mut existing_tags = crypto.decrypt_tags(&entry)?;
        let remove_set: std::collections::HashSet<String> =
            tags.iter().map(|t| t.to_lowercase()).collect();

        let original_count = existing_tags.len();
        existing_tags.retain(|t| !remove_set.contains(&t.to_lowercase()));

        let removed_count = original_count - existing_tags.len();

        if removed_count == 0 {
            println!("No tags removed (tags not found)");
            return Ok(());
        }

        let password_data = crypto.decrypt_entry(&entry)?;
        let description = crypto.decrypt_description(&entry)?;

        let new_entry =
            crypto.create_entry(&password_data, description.as_deref(), Some(&existing_tags))?;

        storage.edit_password(&name, &new_entry)?;
        println!("Removed {} tag(s) from '{}'", removed_count, name);

        Ok(())
    }
}
