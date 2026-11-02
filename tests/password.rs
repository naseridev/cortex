use cortex::core::password::{Password, PasswordCharset};

const SPECIAL_CHARACTERS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

#[test]
fn generator_includes_all_selected_character_classes() -> Result<(), String> {
    let charset = PasswordCharset::from_bits(
        PasswordCharset::UPPERCASE
            | PasswordCharset::LOWERCASE
            | PasswordCharset::DIGITS
            | PasswordCharset::SPECIAL,
    );

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
fn generator_respects_single_class_restriction() -> Result<(), String> {
    let digits_only = PasswordCharset::from_bits(PasswordCharset::DIGITS);
    let generated = Password::generate(20, digits_only)?;
    assert_eq!(generated.len(), 20);
    assert!(generated.chars().all(|c| c.is_ascii_digit()));
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
fn master_password_security_check_enforces_complexity() {
    assert!(Password::security_check("Short1!").is_err());
    assert!(Password::security_check("alllowercase1!").is_err());
    assert!(Password::security_check("ALLUPPERCASE1!").is_err());
    assert!(Password::security_check("NoDigitsHere!").is_err());
    assert!(Password::security_check("NoSpecialChars1").is_err());
    assert!(Password::security_check("ValidMasterPass1!").is_ok());
}

#[test]
fn description_leak_check_detects_password_substrings() {
    assert!(Password::in_desc_check("MySecret99", "hint: mysecret9").is_err());
    assert!(Password::in_desc_check("MySecret99", "unrelated description").is_ok());
    assert!(Password::in_desc_check("ab", "ab").is_ok());
}
