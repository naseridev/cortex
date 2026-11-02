use cortex::core::limits::MAX_NAME_BYTES;
use cortex::core::validation::Validation;

#[test]
fn account_name_validation_blocks_reserved_blank_and_control_chars() {
    assert!(Validation::check_account_name("").is_err());
    assert!(Validation::check_account_name("   ").is_err());
    assert!(Validation::check_account_name("__system").is_err());
    assert!(Validation::check_account_name("bad\nname").is_err());
    assert!(Validation::check_account_name("bidi\u{202e}spoof").is_err());
    assert!(Validation::check_account_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());

    assert!(Validation::check_account_name("valid-account_1").is_ok());
}

#[test]
fn description_validation_blocks_control_and_formatting_chars() {
    assert!(Validation::check_description_text("line1\rline2").is_err());
    assert!(Validation::check_description_text("hidden\u{200b}zero_width").is_err());
    assert!(Validation::check_description_text("Clean description text!").is_ok());
}

#[test]
fn printable_sanitizer_escapes_terminal_injection_sequences() {
    assert_eq!(Validation::printable("safe text"), "safe text");
    assert_eq!(Validation::printable("esc\u{1b}[31m"), "esc\\u{1b}[31m");
    assert_eq!(Validation::printable("rtl\u{202e}override"), "rtl\\u{202e}override");
}