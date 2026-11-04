use cortex::cloud::{
    client::CloudClient,
    provider::{CloudCredentials, ProviderSettings},
};
use tempfile::TempDir;

use crate::common::{TestResult, failure};

#[test]
fn cloud_filenames_are_blake3_hashed_and_hide_plaintext_names() {
    let main_name = CloudClient::vault_filename("personal");
    let bak_name = CloudClient::backup_filename("personal");
    let tmp_name = CloudClient::temp_filename("personal");

    assert!(!main_name.contains("personal"));
    assert!(main_name.ends_with(".cortex"));
    assert!(bak_name.ends_with(".cortex.bak"));
    assert!(tmp_name.ends_with(".cortex.tmp"));
    assert_eq!(main_name.len(), 64 + ".cortex".len());
}

#[test]
fn local_cloud_client_pushes_pulls_and_rotates_backups() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    assert!(client.pull("work")?.is_none());

    client.push("work", b"first_encrypted_snapshot")?;
    assert_eq!(
        client.pull("work")?.as_deref(),
        Some(&b"first_encrypted_snapshot"[..])
    );

    client.push("work", b"second_encrypted_snapshot")?;
    assert_eq!(
        client.pull("work")?.as_deref(),
        Some(&b"second_encrypted_snapshot"[..])
    );

    let backup_path = dir.path().join(CloudClient::backup_filename("work"));
    assert_eq!(std::fs::read(backup_path)?, b"first_encrypted_snapshot");

    Ok(())
}

#[test]
fn cloud_client_rejects_invalid_provider_configuration() -> TestResult {
    let result = CloudClient::from_parts(
        &ProviderSettings::Local {
            root: String::new(),
        },
        &CloudCredentials::default(),
    );

    let error = failure(result)?;
    assert_ne!(error.to_string(), "");

    Ok(())
}
