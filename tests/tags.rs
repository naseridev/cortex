use cortex::core::tags::TagValidator;

#[test]
fn tag_normalization_lowercases_sorts_and_deduplicates() -> Result<(), Box<dyn std::error::Error>> {
    let parsed = TagValidator::parse_and_validate(" Work, FINANCE , work, my-tag_1 ")?;
    assert_eq!(parsed, vec!["finance", "my-tag_1", "work"]);
    Ok(())
}

#[test]
fn tag_validator_rejects_invalid_characters_and_limits() {
    assert!(TagValidator::parse_and_validate("invalid tag with spaces").is_err());
    assert!(TagValidator::parse_and_validate("bad@char").is_err());

    let too_long = "a".repeat(31);
    assert!(TagValidator::parse_and_validate(&too_long).is_err());

    let too_many: Vec<String> = (0..21).map(|i| format!("tag{i}")).collect();
    assert!(TagValidator::validate(&too_many).is_err());
}
