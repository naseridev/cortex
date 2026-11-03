use cortex::commands::account::resolve_name;

use crate::common::TestResult;

#[test]
fn provided_name_is_trimmed_without_prompting() -> TestResult {
    assert_eq!(
        resolve_name(Some("  work  ".to_string()), "Account name: ")?,
        "work"
    );
    Ok(())
}
