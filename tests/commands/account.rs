use cortex::commands::account::resolve_name;

#[test]
fn provided_name_is_trimmed_without_prompting() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        resolve_name(Some("  work  ".to_string()), "Account name: ")?,
        "work"
    );
    Ok(())
}
