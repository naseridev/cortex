use cortex::core::validation::Validation;

#[test]
fn printable_escapes_control_and_hidden_characters() {
    assert_eq!(Validation::printable("ab\u{1b}[31m"), "ab\\u{1b}[31m");
    assert_eq!(Validation::printable("x\u{202e}y"), "x\\u{202e}y");
    assert_eq!(Validation::printable("plain text"), "plain text");
}

#[test]
fn account_names_reject_control_and_hidden_characters() {
    assert!(Validation::check_account_name("bank\nfake").is_err());
    assert!(Validation::check_account_name("bank\u{202e}").is_err());
    assert!(Validation::check_account_name("mail account").is_ok());
}

#[test]
fn descriptions_reject_control_characters() {
    assert!(Validation::check_description_text("line one\rline two").is_err());
    assert!(Validation::check_description_text("normal description").is_ok());
}
