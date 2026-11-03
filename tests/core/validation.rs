use cortex::core::crypto::Crypto;
use cortex::core::limits::MAX_NAME_BYTES;
use cortex::core::storage::Storage;
use cortex::core::validation::Validation;
use tempfile::TempDir;

use crate::common::{TestResult, failure};

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
fn account_name_length_limit_is_inclusive() {
    assert!(Validation::check_account_name(&"x".repeat(MAX_NAME_BYTES)).is_ok());
}

#[test]
fn account_names_may_contain_inner_spaces() {
    assert!(Validation::check_account_name("work account").is_ok());
}

#[test]
fn reserved_prefix_and_blank_detection() {
    assert!(Validation::is_reserved_or_blank(""));
    assert!(Validation::is_reserved_or_blank("  \t "));
    assert!(Validation::is_reserved_or_blank("__"));
    assert!(Validation::is_reserved_or_blank("__config__"));
    assert!(!Validation::is_reserved_or_blank("a"));
    assert!(!Validation::is_reserved_or_blank(" a"));
}

#[test]
fn description_validation_blocks_control_and_formatting_chars() {
    assert!(Validation::check_description_text("line1\rline2").is_err());
    assert!(Validation::check_description_text("line1\nline2").is_err());
    assert!(Validation::check_description_text("tab\tseparated").is_err());
    assert!(Validation::check_description_text("hidden\u{200b}zero_width").is_err());
    assert!(Validation::check_description_text("Clean description text!").is_ok());
}

#[test]
fn printable_sanitizer_escapes_terminal_injection_sequences() {
    assert_eq!(Validation::printable("safe text"), "safe text");
    assert_eq!(Validation::printable("esc\u{1b}[31m"), "esc\\u{1b}[31m");
    assert_eq!(
        Validation::printable("rtl\u{202e}override"),
        "rtl\\u{202e}override"
    );
}

#[test]
fn printable_sanitizer_escapes_every_hidden_formatting_class() {
    for hidden in [
        '\u{061c}', '\u{200b}', '\u{200f}', '\u{2066}', '\u{2069}', '\u{feff}', '\u{7f}',
    ] {
        let sanitized = Validation::printable(&format!("a{hidden}b"));
        assert!(!sanitized.contains(hidden), "{hidden:?}");
        assert!(sanitized.starts_with('a') && sanitized.ends_with('b'));
        assert!(sanitized.contains("\\u{"));
    }
}

#[test]
fn printable_sanitizer_keeps_ordinary_non_ascii_text() {
    let text = "caf\u{e9} \u{4e2d}\u{6587}";
    assert_eq!(Validation::printable(text), text);
}

#[test]
fn account_exists_probe_matches_the_expected_presence() -> TestResult {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("vault.redb"))?;
    let crypto = Crypto::from_key([9u8; 32]);
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;

    Validation::account_exists_probe(&storage, "alpha", false, "should be absent")?;
    let missing = Validation::account_exists_probe(&storage, "alpha", true, "should be present");
    assert_eq!(failure(missing)?.to_string(), "should be present");

    let entry = crypto.create_entry("alpha", b"pass1234", None, None)?;
    storage.create_password("alpha", &entry)?;
    Validation::account_exists_probe(&storage, "alpha", true, "should be present")?;
    Ok(())
}

#[test]
fn account_exists_probe_never_reports_reserved_names_as_present() -> TestResult {
    let dir = TempDir::new()?;
    let storage = Storage::open_at(&dir.path().join("vault.redb"))?;
    let crypto = Crypto::from_key([9u8; 32]);
    storage.init_db(&crypto, &Crypto::encode_salt(&[4u8; 32]))?;

    assert!(Validation::account_exists_probe(&storage, "__init__", true, "reserved").is_err());
    Ok(())
}
