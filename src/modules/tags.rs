pub struct TagValidator;

impl TagValidator {
    pub fn validate(tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if tags.len() > 20 {
            return Err("Maximum 20 tags allowed".into());
        }

        for tag in tags {
            if tag.is_empty() || tag.trim().is_empty() {
                return Err("Tags cannot be empty".into());
            }

            if tag.len() > 30 {
                return Err("Tag length cannot exceed 30 characters".into());
            }

            if !tag
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Err(
                    "Tags can only contain alphanumeric characters, hyphens, and underscores"
                        .into(),
                );
            }
        }

        Ok(())
    }

    pub fn normalize(tags: &[String]) -> Vec<String> {
        let mut normalized: Vec<String> = tags
            .iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();

        normalized.sort();
        normalized.dedup();
        normalized
    }

    pub fn parse_input(input: &str) -> Vec<String> {
        input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}
