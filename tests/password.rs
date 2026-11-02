use cortex::core::password::{Password, PasswordCharset};

const SPECIAL_CHARACTERS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

#[test]
fn generated_password_has_requested_length_and_all_classes() -> Result<(), String> {
    let charset = PasswordCharset::from_bits(
        PasswordCharset::UPPERCASE
            | PasswordCharset::LOWERCASE
            | PasswordCharset::DIGITS
            | PasswordCharset::SPECIAL,
    );
    for _ in 0..50 {
        let password = Password::generate(16, charset)?;
        assert_eq!(password.chars().count(), 16);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| SPECIAL_CHARACTERS.contains(c)));
    }
    Ok(())
}

#[test]
fn generated_digits_only_password_contains_only_digits() -> Result<(), String> {
    let password = Password::generate(24, PasswordCharset::from_bits(PasswordCharset::DIGITS))?;
    assert_eq!(password.chars().count(), 24);
    assert!(password.chars().all(|c| c.is_ascii_digit()));
    Ok(())
}

#[test]
fn generation_rejects_length_shorter_than_required_classes() {
    let charset = PasswordCharset::from_bits(PasswordCharset::UPPERCASE | PasswordCharset::DIGITS);
    assert!(Password::generate(1, charset).is_err());
}

#[test]
fn description_containing_a_password_fragment_is_rejected() {
    assert!(Password::in_desc_check("abc123XYZ", "xxabc1yy").is_err());
    assert!(Password::in_desc_check("abc123XYZ", "a note about mail").is_ok());
}

#[test]
fn short_password_or_description_never_triggers_the_description_check() {
    assert!(Password::in_desc_check("ab", "ab cd").is_ok());
    assert!(Password::in_desc_check("abc123XYZ", "ab").is_ok());
}
