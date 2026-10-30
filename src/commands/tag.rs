use crate::{
    core::types::SecureString,
    modules::{gateway::Gateway, tags::TagValidator},
};
use std::collections::{HashMap, HashSet};

pub struct Tag;

impl Tag {
    pub fn list() -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let mut tag_counts: HashMap<String, usize> = HashMap::new();

        for (name, entry) in storage.list_entries()? {
            let tags = match crypto.decrypt_tags(&entry) {
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

        let mut sorted_tags: Vec<_> = tag_counts.into_iter().collect();
        sorted_tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        println!("\nTags:");
        for (tag, count) in sorted_tags {
            println!("  {tag} ({count})");
        }

        Ok(())
    }

    pub fn add(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") || name.trim().is_empty() {
            return Err("Cannot modify system or empty entries".into());
        }

        let normalized_tags = TagValidator::normalize(tags);
        if normalized_tags.is_empty() {
            return Err("No valid tags provided".into());
        }
        TagValidator::validate(&normalized_tags)?;

        let (storage, crypto) = Gateway::login()?;

        let entry = storage
            .get_password(name)?
            .ok_or_else(|| format!("Entry '{name}' not found"))?;

        let mut existing_tags = crypto.decrypt_tags(&entry)?;
        let existing_set: HashSet<String> =
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

        let decrypted_bytes = crypto.decrypt_entry(&entry)?;
        let password_str = String::from_utf8(decrypted_bytes)?;
        let secure_password = SecureString::new(password_str);
        let description = crypto.decrypt_description(&entry)?;

        let new_entry = crypto.create_entry(
            secure_password.as_bytes(),
            description.as_deref(),
            Some(&normalized_final),
        )?;

        if !storage.edit_password(name, &new_entry)? {
            return Err(format!("Failed to update entry '{name}'").into());
        }
        println!("Added {added_count} tag(s) to '{name}'");

        Ok(())
    }

    pub fn remove(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if name.starts_with("__") || name.trim().is_empty() {
            return Err("Cannot modify system or empty entries".into());
        }

        if tags.is_empty() {
            return Err("No tags specified for removal".into());
        }

        let (storage, crypto) = Gateway::login()?;

        let entry = storage
            .get_password(name)?
            .ok_or_else(|| format!("Entry '{name}' not found"))?;

        let mut existing_tags = crypto.decrypt_tags(&entry)?;
        let remove_set: HashSet<String> = tags.iter().map(|t| t.to_lowercase()).collect();

        let original_count = existing_tags.len();
        existing_tags.retain(|t| !remove_set.contains(&t.to_lowercase()));

        let removed_count = original_count - existing_tags.len();

        if removed_count == 0 {
            println!("No tags removed (tags not found)");
            return Ok(());
        }

        let decrypted_bytes = crypto.decrypt_entry(&entry)?;
        let password_str = String::from_utf8(decrypted_bytes)?;
        let secure_password = SecureString::new(password_str);
        let description = crypto.decrypt_description(&entry)?;

        let remaining_tags = if existing_tags.is_empty() {
            None
        } else {
            Some(existing_tags.as_slice())
        };

        let new_entry = crypto.create_entry(
            secure_password.as_bytes(),
            description.as_deref(),
            remaining_tags,
        )?;

        if !storage.edit_password(name, &new_entry)? {
            return Err(format!("Failed to update entry '{name}'").into());
        }
        println!("Removed {removed_count} tag(s) from '{name}'");

        Ok(())
    }
}
