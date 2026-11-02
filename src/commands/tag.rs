use crate::{
    core::{
        crypto::Crypto,
        storage::Storage,
        tags::TagValidator,
        types::{PasswordEntry, decode_secret_text},
        validation::Validation,
    },
    modules::gateway::Gateway,
};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

pub struct Tag;

impl Tag {
    pub fn list() -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn add(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if Validation::is_reserved_or_blank(name) {
            return Err("Cannot modify system or empty entries".into());
        }

        let requested = TagValidator::normalize(tags);
        if requested.is_empty() {
            return Err("No valid tags provided".into());
        }

        TagValidator::validate(&requested)?;

        let (storage, crypto) = Gateway::login()?;
        let entry = Self::load_entry(&storage, name)?;

        let mut merged_tags = crypto.decrypt_tags(name, &entry)?;
        let existing_keys: HashSet<String> =
            merged_tags.iter().map(|tag| tag.to_lowercase()).collect();

        let mut added_count = 0;
        for tag in requested {
            if !existing_keys.contains(&tag.to_lowercase()) {
                merged_tags.push(tag);
                added_count += 1;
            }
        }

        if added_count == 0 {
            println!("No new tags added (all tags already exist)");
            return Ok(());
        }

        let final_tags = TagValidator::normalize(&merged_tags);
        TagValidator::validate(&final_tags)?;

        Self::rewrite_entry(&storage, &crypto, name, &entry, Some(&final_tags))?;
        println!("Added {added_count} tag(s) to '{name}'");

        Ok(())
    }

    pub fn remove(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if Validation::is_reserved_or_blank(name) {
            return Err("Cannot modify system or empty entries".into());
        }

        if tags.is_empty() {
            return Err("No tags specified for removal".into());
        }

        let (storage, crypto) = Gateway::login()?;
        let entry = Self::load_entry(&storage, name)?;

        let mut remaining_tags = crypto.decrypt_tags(name, &entry)?;
        let removal_keys: HashSet<String> = tags.iter().map(|tag| tag.to_lowercase()).collect();

        let original_count = remaining_tags.len();

        remaining_tags.retain(|tag| !removal_keys.contains(&tag.to_lowercase()));
        let removed_count = original_count - remaining_tags.len();

        if removed_count == 0 {
            println!("No tags removed (tags not found)");
            return Ok(());
        }

        let remaining = (!remaining_tags.is_empty()).then_some(remaining_tags.as_slice());
        Self::rewrite_entry(&storage, &crypto, name, &entry, remaining)?;

        println!("Removed {removed_count} tag(s) from '{name}'");

        Ok(())
    }

    fn load_entry(
        storage: &Storage,
        name: &str,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let entry = storage
            .get_password(name)?
            .ok_or_else(|| format!("Entry '{name}' not found"))?;
        Ok(entry)
    }

    fn rewrite_entry(
        storage: &Storage,
        crypto: &Crypto,
        name: &str,
        entry: &PasswordEntry,
        tags: Option<&[String]>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let decrypted = crypto.decrypt_entry(name, entry)?;
        let password = Zeroizing::new(decode_secret_text(decrypted)?);
        let description = crypto.decrypt_description(name, entry)?;

        let updated =
            crypto.create_entry(name, password.as_bytes(), description.as_deref(), tags)?;
        if !storage.edit_password(name, &updated)? {
            return Err(format!("Failed to update entry '{name}'").into());
        }

        Ok(())
    }
}
