use super::{load_entry, rewrite_entry};
use crate::{
    core::{tags::TagValidator, validation::Validation},
    modules::gateway::Gateway,
};
use std::collections::HashSet;

pub fn execute(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if Validation::is_reserved_or_blank(name) {
        return Err("Cannot modify system or empty entries".into());
    }

    let requested = TagValidator::normalize(tags);
    if requested.is_empty() {
        return Err("No valid tags provided".into());
    }

    TagValidator::validate(&requested)?;

    let (storage, crypto) = Gateway::login()?;
    let entry = load_entry(&storage, name)?;

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

    rewrite_entry(&storage, &crypto, name, &entry, Some(&final_tags))?;
    println!("Added {added_count} tag(s) to '{name}'");

    Ok(())
}
