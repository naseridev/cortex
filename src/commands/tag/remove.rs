use super::{load_entry, rewrite_entry};
use crate::{core::validation::Validation, modules::gateway::Gateway};
use std::collections::HashSet;

pub fn execute(name: &str, tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if Validation::is_reserved_or_blank(name) {
        return Err("Cannot modify system or empty entries".into());
    }

    if tags.is_empty() {
        return Err("No tags specified for removal".into());
    }

    let (storage, crypto) = Gateway::login()?;
    let entry = load_entry(&storage, name)?;

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
    rewrite_entry(&storage, &crypto, name, &entry, remaining)?;

    println!("Removed {removed_count} tag(s) from '{name}'");

    Ok(())
}
