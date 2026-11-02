use cortex::core::accounts::Accounts;

#[test]
fn hashed_filenames_are_deterministic_and_hide_plaintext() {
    let first = Accounts::file_name("personal");
    let second = Accounts::file_name("personal");
    let different = Accounts::file_name("work");

    assert_eq!(first, second);
    assert_ne!(first, different);
    assert!(first.ends_with(".redb"));
    assert!(!first.contains("personal"));
    assert_eq!(first.len(), 64 + ".redb".len());
}