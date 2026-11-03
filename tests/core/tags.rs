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

#[test]
fn parse_input_splits_on_commas_and_drops_blank_segments() {
    assert_eq!(
        TagValidator::parse_input(" a, ,b,, c "),
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
    assert!(TagValidator::parse_input(" , ,").is_empty());
}

#[test]
fn normalize_trims_lowercases_and_removes_blank_and_duplicate_tags() {
    let raw = vec![
        "  Work ".to_string(),
        "work".to_string(),
        String::new(),
        "   ".to_string(),
    ];
    assert_eq!(TagValidator::normalize(&raw), vec!["work".to_string()]);
}

#[test]
fn validate_accepts_exactly_the_tag_count_limit() {
    let at_limit: Vec<String> = (0..20).map(|i| format!("tag{i}")).collect();
    assert!(TagValidator::validate(&at_limit).is_ok());
}

#[test]
fn validate_accepts_exactly_thirty_ascii_characters() {
    assert!(TagValidator::validate(&["a".repeat(30)]).is_ok());
    assert!(TagValidator::validate(&["a".repeat(31)]).is_err());
}

#[test]
fn validate_rejects_blank_and_empty_tags() {
    assert!(TagValidator::validate(&["   ".to_string()]).is_err());
    assert!(TagValidator::validate(&[String::new()]).is_err());
}

#[test]
fn validate_allows_hyphens_and_underscores_but_not_punctuation() {
    assert!(TagValidator::validate(&["a-b_c1".to_string()]).is_ok());
    for bad in ["a.b", "a/b", "a+b", "a b", "a:b"] {
        assert!(TagValidator::validate(&[bad.to_string()]).is_err(), "{bad}");
    }
}

#[test]
fn parse_and_validate_accepts_empty_input_as_no_tags() -> Result<(), Box<dyn std::error::Error>> {
    assert!(TagValidator::parse_and_validate("")?.is_empty());
    Ok(())
}

#[test]
#[ignore = "known defect: the length limit is applied to byte length, not character count"]
fn length_limit_counts_characters_not_bytes() {
    let sixteen_two_byte_chars = "\u{e9}".repeat(16);
    assert!(TagValidator::validate(&[sixteen_two_byte_chars]).is_ok());
}
