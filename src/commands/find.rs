use crate::modules::gateway::Gateway;
use regex::Regex;

pub struct Find;

impl Find {
    pub fn new(
        pattern: String,
        ignore_case: bool,
        names_only: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let entries = storage.search_entries(&pattern)?;
        let regex_flags = if ignore_case { "(?i)" } else { "" };
        let full_pattern = format!("{}{}", regex_flags, regex::escape(&pattern));
        let re = Regex::new(&full_pattern).map_err(|e| format!("Invalid search pattern: {}", e))?;

        let mut results = Vec::new();

        for (name, entry) in entries {
            let name_match = re.is_match(&name);

            let (description, desc_match) = if names_only {
                (None, false)
            } else if name_match {
                let desc = crypto.decrypt_description(&entry).unwrap_or(None);
                (desc, false)
            } else {
                match crypto.decrypt_description(&entry) {
                    Ok(Some(desc)) => {
                        let desc_match = re.is_match(&desc);
                        (Some(desc), desc_match)
                    }
                    Ok(None) => (None, false),
                    Err(_) => continue,
                }
            };

            if name_match || desc_match {
                results.push((name, description, name_match, desc_match));
            }
        }

        results.sort_by(|a, b| a.0.cmp(&b.0));

        if results.is_empty() {
            println!("No matches found for: {}", pattern);
            return Ok(());
        }

        println!();
        println!("Found {} match(es) for: {}", results.len(), pattern);

        if results.len() > 20 {
            println!("(Showing first 20 results)");
        }

        println!();

        for (name, description, name_match, desc_match) in results.iter().take(20) {
            println!("Entry: {}", name);

            if *name_match && *desc_match {
                println!("  >> Matches: name and description");
            } else if *name_match {
                println!("  >> Matches: name");
            } else if *desc_match {
                println!("  >> Matches: description");
            }

            if let Some(desc) = description {
                let display_desc = if desc.len() > 60 {
                    format!("{}...", &desc[..57])
                } else {
                    desc.clone()
                };
                println!("  Description: {}", display_desc);
            }

            println!();
        }

        if results.len() > 20 {
            println!("... and {} more results", results.len() - 20);
        }

        Ok(())
    }
}
