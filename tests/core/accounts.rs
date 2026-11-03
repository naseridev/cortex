use cortex::core::accounts::Accounts;
use std::path::Path;

use crate::common::TestResult;

#[test]
fn hashed_filenames_are_deterministic_and_hide_plaintext() {
    let first = Accounts::file_name("personal");
    let second = Accounts::file_name("personal");
    let different = Accounts::file_name("work");

    assert_eq!(first, second);
    assert_ne!(first, different);
    assert!(
        Path::new(&first)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("redb"))
    );
    assert!(!first.contains("personal"));
    assert_eq!(first.len(), 64 + ".redb".len());
}

#[test]
fn file_name_is_blake3_hex_of_the_account_name() {
    let expected = format!("{}.redb", blake3::hash(b"personal").to_hex());
    assert_eq!(Accounts::file_name("personal"), expected);
}

#[test]
fn file_names_are_case_sensitive() {
    assert_ne!(Accounts::file_name("Work"), Accounts::file_name("work"));
}

#[test]
fn file_name_is_hex_for_empty_and_non_ascii_names() -> TestResult {
    for name in ["", "caf\u{e9}", "\u{4e2d}\u{6587}"] {
        let file = Accounts::file_name(name);
        let stem = file.strip_suffix(".redb").ok_or("missing redb suffix")?;
        assert_eq!(stem.len(), 64);
        assert!(stem.chars().all(|c| c.is_ascii_hexdigit()));
    }
    Ok(())
}
