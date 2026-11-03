pub struct TagValidator;

const MAX_TAGS: usize = 20;
const MAX_TAG_LENGTH: usize = 30;

impl TagValidator {
    pub fn validate(tags: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        if tags.len() > MAX_TAGS {
            return Err("Maximum 20 tags allowed".into());
        }

        for tag in tags {
            Self::validate_tag(tag)?;
        }

        Ok(())
    }

    fn validate_tag(tag: &str) -> Result<(), Box<dyn std::error::Error>> {
        if tag.trim().is_empty() {
            return Err("Tags cannot be empty".into());
        }

        if tag.chars().count() > MAX_TAG_LENGTH {
            return Err("Tag length cannot exceed 30 characters".into());
        }

        if !tag
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Tags can only contain alphanumeric characters, hyphens, and underscores".into(),
            );
        }

        Ok(())
    }

    #[must_use]
    pub fn normalize(tags: &[String]) -> Vec<String> {
        let mut normalized: Vec<String> = tags
            .iter()
            .map(|tag| tag.trim().to_lowercase())
            .filter(|tag| !tag.is_empty())
            .collect();

        normalized.sort();
        normalized.dedup();
        normalized
    }

    #[must_use]
    pub fn parse_input(input: &str) -> Vec<String> {
        input
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect()
    }

    pub fn parse_and_validate(input: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let normalized = Self::normalize(&Self::parse_input(input));
        Self::validate(&normalized)?;
        Ok(normalized)
    }
}
