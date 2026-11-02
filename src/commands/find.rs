use crate::{
    core::{crypto::Crypto, types::PasswordEntry, validation::Validation},
    modules::gateway::Gateway,
};
use regex::{Regex, RegexBuilder};

const MAX_SHOWN_RESULTS: usize = 20;
const MAX_PREVIEW_CHARS: usize = 60;
const REGEX_SIZE_LIMIT_BYTES: usize = 1024 * 1024;

pub struct Find;

struct SearchHit {
    name: String,
    description: Option<String>,
    tags: Vec<String>,
    name_matched: bool,
    description_matched: bool,
    tag_matched: bool,
}

impl Find {
    pub fn execute(
        pattern: &str,
        ignore_case: bool,
        names_only: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (storage, crypto) = Gateway::login()?;

        let entries = storage.search_entries(pattern)?;
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(ignore_case)
            .size_limit(REGEX_SIZE_LIMIT_BYTES)
            .build()
            .map_err(|error| format!("Invalid search pattern: {error}"))?;

        let mut hits: Vec<SearchHit> = entries
            .into_iter()
            .filter_map(|(name, entry)| Self::examine(&crypto, &regex, name, &entry, names_only))
            .collect();
        hits.sort_by(|a, b| a.name.cmp(&b.name));

        if hits.is_empty() {
            println!("No matches found for: {pattern}");
            return Ok(());
        }

        println!("\nFound {} match(es) for: {}", hits.len(), pattern);
        if hits.len() > MAX_SHOWN_RESULTS {
            println!("(Showing first {MAX_SHOWN_RESULTS} results)");
        }

        println!();

        for hit in hits.iter().take(MAX_SHOWN_RESULTS) {
            Self::print_hit(hit);
        }

        if hits.len() > MAX_SHOWN_RESULTS {
            println!("... and {} more results", hits.len() - MAX_SHOWN_RESULTS);
        }

        Ok(())
    }

    fn examine(
        crypto: &Crypto,
        regex: &Regex,
        name: String,
        entry: &PasswordEntry,
        names_only: bool,
    ) -> Option<SearchHit> {
        let name_matched = regex.is_match(&name);

        let description = if names_only {
            None
        } else {
            match crypto.decrypt_description(&name, entry) {
                Ok(description) => description,
                Err(error) => {
                    eprintln!("Warning: skipping description for '{name}': {error}");
                    None
                }
            }
        };

        let description_matched = description
            .as_deref()
            .is_some_and(|text| regex.is_match(text));

        let tags = match crypto.decrypt_tags(&name, entry) {
            Ok(tags) => tags,
            Err(error) => {
                eprintln!("Warning: skipping tags for '{name}': {error}");
                Vec::new()
            }
        };

        let tag_matched = !names_only && tags.iter().any(|tag| regex.is_match(tag));

        if name_matched || description_matched || tag_matched {
            Some(SearchHit {
                name,
                description,
                tags,
                name_matched,
                description_matched,
                tag_matched,
            })
        } else {
            None
        }
    }

    fn print_hit(hit: &SearchHit) {
        println!("Entry: {}", Validation::printable(&hit.name));

        let labels = Self::match_labels(hit);
        if !labels.is_empty() {
            println!("  >> Matches: {}", labels.join(" and "));
        }

        if let Some(description) = &hit.description {
            println!(
                "  Description: {}",
                Validation::printable(&Self::preview(description))
            );
        }

        if !hit.tags.is_empty() {
            println!("  Tags: {}", hit.tags.join(", "));
        }

        println!();
    }

    fn match_labels(hit: &SearchHit) -> Vec<&'static str> {
        [
            (hit.name_matched, "name"),
            (hit.description_matched, "description"),
            (hit.tag_matched, "tags"),
        ]
        .into_iter()
        .filter(|(matched, _)| *matched)
        .map(|(_, label)| label)
        .collect()
    }

    fn preview(description: &str) -> String {
        if description.chars().count() > MAX_PREVIEW_CHARS {
            let head: String = description.chars().take(MAX_PREVIEW_CHARS - 3).collect();
            format!("{head}...")
        } else {
            description.to_string()
        }
    }
}
