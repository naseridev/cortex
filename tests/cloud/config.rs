use cortex::cloud::{
    config::{CloudConfig, CloudRemote},
    provider::{CloudCredentials, ProviderSettings},
};
use std::cell::Cell;
use std::collections::BTreeMap;
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

fn fallback_remote(name: &str, fallback: Option<Vec<u8>>) -> CloudRemote {
    CloudRemote {
        name: name.to_string(),
        settings: ProviderSettings::Local {
            root: String::from("/unused"),
        },
        fallback_credentials: fallback,
        accounts: BTreeMap::new(),
    }
}

#[test]
fn keyring_secret_takes_precedence_and_skips_the_passphrase_prompt() -> TestResult {
    let sealed = CloudConfig::seal_credentials(
        &CloudCredentials::with_token(TOKEN.to_string()),
        &passphrase(PASSPHRASE),
    )?;
    let remote = fallback_remote("keyring-first", Some(sealed));
    let stored = postcard::to_allocvec(&CloudCredentials::with_token("keyring-token".to_string()))?;
    let prompted = Cell::new(false);

    let creds = CloudConfig::load_credentials_from(
        &remote,
        |_: &str| Some(stored),
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    )?;

    assert_eq!(creds.token.as_deref(), Some("keyring-token"));
    assert!(!prompted.get());
    Ok(())
}

#[test]
fn corrupt_keyring_secret_is_reported_instead_of_falling_back() -> TestResult {
    let sealed = CloudConfig::seal_credentials(
        &CloudCredentials::with_token(TOKEN.to_string()),
        &passphrase(PASSPHRASE),
    )?;
    let remote = fallback_remote("corrupt-keyring", Some(sealed));
    let prompted = Cell::new(false);

    let error = failure(CloudConfig::load_credentials_from(
        &remote,
        |_: &str| Some(vec![0xff]),
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    ))?;
    assert!(error.to_string().contains("deserialize"));
    assert!(!prompted.get());
    Ok(())
}

#[test]
fn no_secret_fallback_needs_no_passphrase() -> TestResult {
    let remote = fallback_remote("no-secret", Some(Vec::new()));
    let prompted = Cell::new(false);

    let creds = CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    )?;

    assert!(CloudConfig::holds_no_secret(&creds));
    assert!(!prompted.get());
    Ok(())
}

#[test]
fn missing_credentials_are_reported_without_prompting() -> TestResult {
    let remote = fallback_remote("missing", None);
    let prompted = Cell::new(false);

    let error = failure(CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    ))?;
    assert!(error.to_string().contains("were not found"));
    assert!(!prompted.get());
    Ok(())
}

#[test]
fn sealed_fallback_is_opened_with_the_prompted_passphrase() -> TestResult {
    let original = CloudCredentials::with_password(Some(SECRET_PASSWORD.to_string()));
    let sealed = CloudConfig::seal_credentials(&original, &passphrase(PASSPHRASE))?;
    let remote = fallback_remote("sealed", Some(sealed));
    let prompts = Cell::new(0);

    let creds = CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || {
            prompts.set(prompts.get() + 1);
            Ok(passphrase(PASSPHRASE))
        },
    )?;

    assert_eq!(creds.password.as_deref(), Some(SECRET_PASSWORD));
    assert_eq!(prompts.get(), 1);
    Ok(())
}

#[test]
fn sealed_fallback_rejects_a_wrong_prompted_passphrase() -> TestResult {
    let sealed = CloudConfig::seal_credentials(
        &CloudCredentials::with_token(TOKEN.to_string()),
        &passphrase(PASSPHRASE),
    )?;
    let remote = fallback_remote("wrong-passphrase", Some(sealed));

    let error = failure(CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || Ok(passphrase(WRONG_PASSPHRASE)),
    ))?;
    assert!(error.to_string().contains("passphrase"));
    Ok(())
}

#[test]
fn unsupported_fallback_is_rejected_before_prompting() -> TestResult {
    let remote = fallback_remote("unsupported", Some(vec![0xff, 0x13, 0x37]));
    let prompted = Cell::new(false);

    let error = failure(CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    ))?;
    assert!(error.to_string().contains("unsupported format"));
    assert!(!prompted.get());
    Ok(())
}

#[test]
fn legacy_plaintext_fallback_is_rejected_before_prompting() -> TestResult {
    let legacy = postcard::to_allocvec(&CloudCredentials::with_password(Some(
        SECRET_PASSWORD.to_string(),
    )))?;
    let remote = fallback_remote("legacy", Some(legacy));
    let prompted = Cell::new(false);

    let error = failure(CloudConfig::load_credentials_from(
        &remote,
        |_: &str| None,
        || {
            prompted.set(true);
            Ok(passphrase(PASSPHRASE))
        },
    ))?;
    assert!(error.to_string().contains("unsupported format"));
    assert!(!prompted.get());
    Ok(())
}
