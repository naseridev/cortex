use cortex::security::password::{Password, PasswordCharset};

use crate::common::{TestResult, failure};

const SPECIAL_CHARACTERS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

fn all_classes() -> PasswordCharset {
    PasswordCharset::from_bits(
        PasswordCharset::UPPERCASE
            | PasswordCharset::LOWERCASE
            | PasswordCharset::DIGITS
            | PasswordCharset::SPECIAL,
    )
}

#[test]
fn generator_includes_all_selected_character_classes() -> TestResult {
    let charset = all_classes();

    for _ in 0..30 {
        let generated = Password::generate(16, charset)?;
        assert_eq!(generated.chars().count(), 16);
        assert!(generated.chars().any(|c| c.is_ascii_uppercase()));
        assert!(generated.chars().any(|c| c.is_ascii_lowercase()));
        assert!(generated.chars().any(|c| c.is_ascii_digit()));
        assert!(generated.chars().any(|c| SPECIAL_CHARACTERS.contains(c)));
    }
    Ok(())
}

#[test]
fn generator_respects_single_class_restriction() -> TestResult {
    let digits_only = PasswordCharset::from_bits(PasswordCharset::DIGITS);
    let generated = Password::generate(20, digits_only)?;
    assert_eq!(generated.len(), 20);
    assert!(generated.chars().all(|c| c.is_ascii_digit()));
    Ok(())
}

#[test]
fn generator_output_uses_only_the_selected_classes() -> TestResult {
    let charset = PasswordCharset::from_bits(PasswordCharset::LOWERCASE | PasswordCharset::DIGITS);

    for _ in 0..20 {
        let generated = Password::generate(64, charset)?;
        assert!(
            generated
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }
    Ok(())
}

#[test]
fn generator_without_flags_falls_back_to_every_class() -> TestResult {
    let no_flags = PasswordCharset::from_bits(0);

    for _ in 0..20 {
        let generated = Password::generate(16, no_flags)?;
        assert!(generated.chars().any(|c| c.is_ascii_uppercase()));
        assert!(generated.chars().any(|c| c.is_ascii_lowercase()));
        assert!(generated.chars().any(|c| c.is_ascii_digit()));
        assert!(generated.chars().any(|c| SPECIAL_CHARACTERS.contains(c)));
    }
    Ok(())
}

#[test]
fn generator_accepts_length_equal_to_class_count() -> TestResult {
    let generated = Password::generate(4, all_classes())?;
    assert_eq!(generated.chars().count(), 4);
    assert!(generated.chars().any(|c| c.is_ascii_uppercase()));
    assert!(generated.chars().any(|c| c.is_ascii_lowercase()));
    assert!(generated.chars().any(|c| c.is_ascii_digit()));
    assert!(generated.chars().any(|c| SPECIAL_CHARACTERS.contains(c)));
    Ok(())
}

#[test]
fn generator_rejects_length_smaller_than_required_classes() {
    let charset = PasswordCharset::from_bits(
        PasswordCharset::UPPERCASE | PasswordCharset::LOWERCASE | PasswordCharset::DIGITS,
    );
    assert!(Password::generate(2, charset).is_err());
}

#[test]
fn generator_rejects_zero_length() {
    assert!(Password::generate(0, all_classes()).is_err());
}

#[test]
fn generator_outputs_differ_between_calls() -> TestResult {
    let first = Password::generate(32, all_classes())?;
    let second = Password::generate(32, all_classes())?;
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn charset_flags_report_only_selected_classes() {
    let charset = PasswordCharset::from_bits(PasswordCharset::UPPERCASE | PasswordCharset::DIGITS);
    assert!(charset.uppercase());
    assert!(!charset.lowercase());
    assert!(charset.digits());
    assert!(!charset.special());
}

#[test]
fn empty_charset_reports_no_classes() {
    let charset = PasswordCharset::from_bits(0);
    assert!(!charset.uppercase());
    assert!(!charset.lowercase());
    assert!(!charset.digits());
    assert!(!charset.special());
}

#[test]
fn master_password_security_check_enforces_complexity() {
    assert!(Password::security_check("Short1!").is_err());
    assert!(Password::security_check("alllowercase1!").is_err());
    assert!(Password::security_check("ALLUPPERCASE1!").is_err());
    assert!(Password::security_check("NoDigitsHere!").is_err());
    assert!(Password::security_check("NoSpecialChars1").is_err());
    assert!(Password::security_check("ValidMasterPass1!").is_ok());
}

#[test]
fn master_password_security_check_names_each_missing_class() -> TestResult {
    assert!(failure(Password::security_check("alllowercase1!"))?.contains("uppercase letter"));
    assert!(failure(Password::security_check("ALLUPPERCASE1!"))?.contains("lowercase letter"));
    assert!(failure(Password::security_check("NoDigitsHere!"))?.contains("digit"));
    assert!(failure(Password::security_check("NoSpecialChars1"))?.contains("special character"));
    Ok(())
}

#[test]
fn master_password_security_check_requires_minimum_length() -> TestResult {
    assert!(failure(Password::security_check("Abc1!xy"))?.contains("at least 8 characters"));
    assert!(Password::security_check("Abc1!xyz").is_ok());
    Ok(())
}

#[test]
fn length_check_enforces_the_exact_minimum() -> TestResult {
    assert!(Password::length_check("1234567", 8).is_err());
    Password::length_check("12345678", 8)?;
    Ok(())
}

#[test]
fn match_check_rejects_different_inputs() -> TestResult {
    assert!(Password::match_check("alpha", "beta").is_err());
    Password::match_check("alpha", "alpha")?;
    Ok(())
}

#[test]
fn description_leak_check_detects_password_substrings() {
    assert!(Password::in_desc_check("MySecret99", "hint: mysecret9").is_err());
    assert!(Password::in_desc_check("MySecret99", "unrelated description").is_ok());
    assert!(Password::in_desc_check("ab", "ab").is_ok());
}

#[test]
fn description_leak_check_is_case_insensitive() {
    assert!(Password::in_desc_check("MySecret99", "MYSECRET9 hint").is_err());
}

#[test]
fn description_leak_check_flags_a_fragment_of_half_the_password() {
    assert!(Password::in_desc_check("abcdefgh", "xxcdefxx").is_err());
}

#[test]
fn description_leak_check_ignores_fragments_below_the_window() {
    assert!(Password::in_desc_check("abcdefgh", "bcdxx").is_ok());
}

#[test]
fn description_leak_check_flags_the_full_password() {
    assert!(Password::in_desc_check("Passw0rd!", "my Passw0rd! note").is_err());
}
