use cortex::cloud::{config::CloudConfig, provider::CloudCredentials};
use zeroize::Zeroizing;

use crate::common::{TestResult, failure};

const SECRET_PASSWORD: &str = "Remote-Secret-99";
const PASSPHRASE: &str = "Passphrase-Check-42!";
const WRONG_PASSPHRASE: &str = "Wrong-Passphrase-1!";
const TOKEN: &str = "token-value-123";

fn passphrase(value: &str) -> Zeroizing<String> {
    Zeroizing::new(value.to_string())
}

#[test]
fn sealed_credentials_hide_secret_and_round_trip_with_passphrase() -> TestResult {
    let creds = CloudCredentials::with_password(Some(SECRET_PASSWORD.to_string()));
    let sealed = CloudConfig::seal_credentials(&creds, &passphrase(PASSPHRASE))?;

    let needle = SECRET_PASSWORD.as_bytes();
    assert!(!sealed.windows(needle.len()).any(|window| window == needle));

    let opened = CloudConfig::open_credentials(&sealed, &passphrase(PASSPHRASE))?;
    assert_eq!(opened.password.as_deref(), Some(SECRET_PASSWORD));
    Ok(())
}

#[test]
fn sealed_credentials_reject_wrong_passphrase() -> TestResult {
    let creds = CloudCredentials::with_token(TOKEN.to_string());
    let sealed = CloudConfig::seal_credentials(&creds, &passphrase(PASSPHRASE))?;

    let error = failure(CloudConfig::open_credentials(
        &sealed,
        &passphrase(WRONG_PASSPHRASE),
    ))?;
    assert!(error.to_string().contains("passphrase"));
    Ok(())
}

#[test]
fn legacy_plaintext_credentials_are_rejected_as_unsupported() -> TestResult {
    let creds = CloudCredentials::with_password(Some(SECRET_PASSWORD.to_string()));
    let legacy = postcard::to_allocvec(&creds)?;

    let error = failure(CloudConfig::open_credentials(
        &legacy,
        &passphrase(PASSPHRASE),
    ))?;
    assert!(error.to_string().contains("unsupported format"));
    Ok(())
}

#[test]
fn credentials_without_any_secret_are_detected() {
    assert!(CloudConfig::holds_no_secret(&CloudCredentials::default()));
    assert!(!CloudConfig::holds_no_secret(
        &CloudCredentials::with_token(TOKEN.to_string())
    ));
}