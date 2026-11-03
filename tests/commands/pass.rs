use cortex::commands::pass::execute;
use cortex::core::limits::MIN_ACCOUNT_PASSWORD_LENGTH;
use cortex::core::password::PasswordCharset;

use crate::common::{TestResult, failure};

fn all_classes() -> PasswordCharset {
    PasswordCharset::from_bits(
        PasswordCharset::UPPERCASE
            | PasswordCharset::LOWERCASE
            | PasswordCharset::DIGITS
            | PasswordCharset::SPECIAL,
    )
}

#[test]
fn rejects_lengths_below_the_minimum() -> TestResult {
    let error = failure(execute(MIN_ACCOUNT_PASSWORD_LENGTH - 1, 1, all_classes()))?;
    assert!(error.to_string().contains("must be at least 8 characters"));
    Ok(())
}

#[test]
fn rejects_lengths_above_the_maximum() -> TestResult {
    let error = failure(execute(129, 1, all_classes()))?;
    assert_eq!(
        error.to_string(),
        "Password length too long (max 128 chars)."
    );
    Ok(())
}

#[test]
fn rejects_counts_outside_the_supported_range() {
    assert_eq!(
        execute(16, 0, all_classes()).err().map(|e| e.to_string()),
        Some("Count must be between 1 and 50.".to_string())
    );
    assert_eq!(
        execute(16, 51, all_classes()).err().map(|e| e.to_string()),
        Some("Count must be between 1 and 50.".to_string())
    );
}

#[test]
fn accepts_the_boundary_values() -> TestResult {
    execute(MIN_ACCOUNT_PASSWORD_LENGTH, 1, all_classes())?;
    execute(128, 1, all_classes())?;
    execute(16, 50, all_classes())?;
    Ok(())
}

#[test]
fn digit_only_generation_is_accepted() -> TestResult {
    execute(12, 2, PasswordCharset::from_bits(PasswordCharset::DIGITS))?;
    Ok(())
}
