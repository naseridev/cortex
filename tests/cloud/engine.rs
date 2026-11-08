use cortex::cloud::engine::{SyncEngine, SyncState, SyncStatus};
use cortex::{domain::types::PasswordEntry, security::crypto::Crypto};

use crate::common::TestResult;

fn sample_entry(
    crypto: &Crypto,
    name: &str,
    pass: &str,
    timestamp: u64,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let mut entry = crypto.create_entry(name, pass.as_bytes(), Some("desc"), None)?;
    entry.timestamp = timestamp;
    Ok(entry)
}

#[test]
fn merge_resolves_conflicts_by_newest_timestamp_across_keys() -> TestResult {
    let local_crypto = Crypto::from_key([1u8; 32]);
    let remote_crypto = Crypto::from_key([2u8; 32]);

    let local = SyncState {
        entries: vec![
            (
                "github".to_string(),
                sample_entry(&local_crypto, "github", "local_newer", 200)?,
            ),
            (
                "mail".to_string(),
                sample_entry(&local_crypto, "mail", "local_older", 100)?,
            ),
        ],
        tombstones: Vec::new(),
    };

    let remote = SyncState {
        entries: vec![
            (
                "github".to_string(),
                sample_entry(&remote_crypto, "github", "remote_older", 150)?,
            ),
            (
                "mail".to_string(),
                sample_entry(&remote_crypto, "mail", "remote_newer", 300)?,
            ),
            (
                "aws".to_string(),
                sample_entry(&remote_crypto, "aws", "remote_only", 250)?,
            ),
        ],
        tombstones: Vec::new(),
    };

    let report = SyncEngine::merge(&local, &local_crypto, &remote, &remote_crypto, false)?;
    assert_eq!(report.added_from_remote, 1);
    assert_eq!(report.updated_from_remote, 1);
    assert_eq!(report.kept_local, 1);
    assert_eq!(report.entries.len(), 3);

    for (name, entry) in &report.entries {
        let decrypted = local_crypto.decrypt_entry(name, entry)?;
        match name.as_str() {
            "aws" => assert_eq!(decrypted, b"remote_only"),
            "github" => assert_eq!(decrypted, b"local_newer"),
            "mail" => assert_eq!(decrypted, b"remote_newer"),
            other => return Err(format!("unexpected entry {other}").into()),
        }
    }

    Ok(())
}

#[test]
fn evaluate_status_detects_fast_forward_and_divergence() -> TestResult {
    let crypto = Crypto::from_key([7u8; 32]);
    let e1 = sample_entry(&crypto, "alpha", "pass1234", 100)?;
    let e2 = sample_entry(&crypto, "alpha", "pass5678", 200)?;
    let e3 = sample_entry(&crypto, "beta", "pass9999", 250)?;

    let local = SyncState {
        entries: vec![("alpha".to_string(), e2)],
        tombstones: Vec::new(),
    };
    let remote = SyncState {
        entries: vec![("alpha".to_string(), e1), ("beta".to_string(), e3)],
        tombstones: Vec::new(),
    };

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, None, [1u8; 32], [2u8; 32]),
        SyncStatus::Diverged
    );

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, Some([1u8; 32]), [1u8; 32], [2u8; 32]),
        SyncStatus::RemoteAhead
    );

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, Some([2u8; 32]), [1u8; 32], [2u8; 32]),
        SyncStatus::LocalAhead
    );

    Ok(())
}
