use cortex::cloud::{
    client::{CloudClient, Precondition},
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
fn push_aborts_when_the_backup_cannot_be_written() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    client.push("work", b"first_snapshot")?;

    std::fs::create_dir(dir.path().join(CloudClient::backup_filename("work")))?;

    let error = failure(client.push("work", b"second_snapshot"))?;
    assert!(error.to_string().contains("backup"));

    assert_eq!(
        client.pull("work")?.as_deref(),
        Some(&b"first_snapshot"[..])
    );
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

#[test]
fn absent_precondition_refuses_to_replace_a_vault_created_elsewhere() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let device_a = CloudClient::from_parts(&settings, &CloudCredentials::default())?;
    let device_b = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    device_a.push_with("work", b"device_a_snapshot", Precondition::Absent)?;

    let error = failure(device_b.push_with("work", b"device_b_snapshot", Precondition::Absent))?;
    assert!(error.to_string().contains("changed during the upload"));
    assert_eq!(
        device_a.pull("work")?.as_deref(),
        Some(&b"device_a_snapshot"[..])
    );
    Ok(())
}

#[test]
fn unchanged_precondition_rejects_upload_when_remote_moved_after_fetch() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let device_a = CloudClient::from_parts(&settings, &CloudCredentials::default())?;
    let device_b = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    device_a.push("work", b"shared_snapshot")?;
    let observed = device_b.fetch("work")?.ok_or("vault should exist")?;

    device_a.push("work", b"concurrent_snapshot")?;

    let error = failure(device_b.push_with(
        "work",
        b"merged_snapshot",
        Precondition::Unchanged(&observed),
    ))?;
    assert!(error.to_string().contains("changed during the upload"));
    assert_eq!(
        device_a.pull("work")?.as_deref(),
        Some(&b"concurrent_snapshot"[..])
    );
    Ok(())
}

#[test]
fn unchanged_precondition_rejects_upload_when_vault_was_removed_after_fetch() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    client.push("work", b"first_snapshot")?;
    let observed = client.fetch("work")?.ok_or("vault should exist")?;
    std::fs::remove_file(dir.path().join(CloudClient::vault_filename("work")))?;

    let error = failure(client.push_with(
        "work",
        b"replacement_snapshot",
        Precondition::Unchanged(&observed),
    ))?;
    assert!(error.to_string().contains("changed during the upload"));
    assert!(client.pull("work")?.is_none());
    Ok(())
}

#[test]
fn guarded_upload_succeeds_when_remote_is_unchanged_and_backs_up_observed_version() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    client.push("work", b"first_snapshot")?;
    let observed = client.fetch("work")?.ok_or("vault should exist")?;

    client.push_with(
        "work",
        b"second_snapshot",
        Precondition::Unchanged(&observed),
    )?;

    assert_eq!(
        client.pull("work")?.as_deref(),
        Some(&b"second_snapshot"[..])
    );
    assert_eq!(
        std::fs::read(dir.path().join(CloudClient::backup_filename("work")))?,
        b"first_snapshot"
    );
    Ok(())
}

#[test]
fn absent_precondition_creates_a_vault_when_none_exists() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    client.push_with("work", b"fresh_snapshot", Precondition::Absent)?;

    assert_eq!(
        client.pull("work")?.as_deref(),
        Some(&b"fresh_snapshot"[..])
    );
    assert!(
        !dir.path()
            .join(CloudClient::backup_filename("work"))
            .exists()
    );
    Ok(())
}

#[test]
fn rejected_guarded_upload_leaves_backup_and_temp_objects_untouched() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    client.push("work", b"v1")?;
    client.push("work", b"v2")?;
    let observed = client.fetch("work")?.ok_or("vault should exist")?;
    client.push("work", b"v3")?;
    client.push("work", b"v4")?;

    let error = failure(client.push_with("work", b"merged", Precondition::Unchanged(&observed)))?;
    assert!(error.to_string().contains("changed during the upload"));
    assert_eq!(
        std::fs::read(dir.path().join(CloudClient::backup_filename("work")))?,
        b"v3"
    );
    assert_eq!(client.pull("work")?.as_deref(), Some(&b"v4"[..]));
    assert!(!dir.path().join(CloudClient::temp_filename("work")).exists());
    Ok(())
}

#[test]
fn fetch_reports_the_same_bytes_as_pull() -> TestResult {
    let dir = TempDir::new()?;
    let settings = ProviderSettings::Local {
        root: dir.path().display().to_string(),
    };
    let client = CloudClient::from_parts(&settings, &CloudCredentials::default())?;

    assert!(client.fetch("work")?.is_none());
    client.push("work", b"stored_snapshot")?;
    let fetched = client.fetch("work")?.ok_or("vault should exist")?;
    assert_eq!(fetched.bytes, b"stored_snapshot");
    assert_eq!(Some(fetched.bytes), client.pull("work")?);
    Ok(())
}
