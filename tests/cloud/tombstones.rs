use cortex::cloud::engine::{SyncEngine, SyncState, SyncStatus};
use cortex::core::{crypto::Crypto, types::PasswordEntry};

use crate::common::TestResult;

fn sample_entry(
    crypto: &Crypto,
    name: &str,
    pass: &str,
    timestamp: u64,
) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
    let mut entry = crypto.create_entry(name, pass.as_bytes(), None, None)?;
    entry.timestamp = timestamp;
    Ok(entry)
}

fn names(entries: &[(String, PasswordEntry)]) -> Vec<&str> {
    entries.iter().map(|(name, _)| name.as_str()).collect()
}

#[test]
fn local_deletion_is_not_undone_by_an_older_remote_entry() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: vec![(
            "beta".to_string(),
            sample_entry(&crypto, "beta", "beta_pass", 100)?,
        )],
        tombstones: vec![("alpha".to_string(), 300)],
    };
    let remote = SyncState {
        entries: vec![
            (
                "alpha".to_string(),
                sample_entry(&crypto, "alpha", "alpha_pass", 200)?,
            ),
            (
                "beta".to_string(),
                sample_entry(&crypto, "beta", "beta_pass", 100)?,
            ),
        ],
        tombstones: Vec::new(),
    };

    let report = SyncEngine::merge(&local, &crypto, &remote, &crypto, true)?;
    assert_eq!(names(&report.entries), ["beta"]);
    assert_eq!(report.tombstones, vec![("alpha".to_string(), 300)]);
    assert_eq!(report.removed_from_remote, 0);
    Ok(())
}

#[test]
fn remote_deletion_removes_an_older_local_entry() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "alpha_pass", 100)?,
        )],
        tombstones: Vec::new(),
    };
    let remote = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };

    let report = SyncEngine::merge(&local, &crypto, &remote, &crypto, true)?;
    assert_eq!(report.entries.len(), 0);
    assert_eq!(report.tombstones, vec![("alpha".to_string(), 200)]);
    assert_eq!(report.removed_from_remote, 1);
    Ok(())
}

#[test]
fn deletion_wins_a_timestamp_tie() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "alpha_pass", 200)?,
        )],
        tombstones: Vec::new(),
    };
    let remote = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };

    let report = SyncEngine::merge(&local, &crypto, &remote, &crypto, true)?;
    assert_eq!(report.entries.len(), 0);
    assert_eq!(report.tombstones, vec![("alpha".to_string(), 200)]);
    Ok(())
}

#[test]
fn newer_remote_entry_recreates_a_deleted_name() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };
    let remote = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "recreated_pass", 300)?,
        )],
        tombstones: Vec::new(),
    };

    let report = SyncEngine::merge(&local, &crypto, &remote, &crypto, true)?;
    assert_eq!(report.tombstones, Vec::new());
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.updated_from_remote, 1);
    let decrypted = crypto.decrypt_entry("alpha", &report.entries[0].1)?;
    assert_eq!(decrypted, b"recreated_pass");
    Ok(())
}

#[test]
fn deletion_without_a_base_is_reported_as_local_ahead() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 300)],
    };
    let remote = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "alpha_pass", 200)?,
        )],
        tombstones: Vec::new(),
    };

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, None, [1u8; 32], [2u8; 32]),
        SyncStatus::LocalAhead
    );
    Ok(())
}

#[test]
fn remote_deletion_without_a_base_is_reported_as_remote_ahead() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "alpha_pass", 100)?,
        )],
        tombstones: Vec::new(),
    };
    let remote = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, None, [1u8; 32], [2u8; 32]),
        SyncStatus::RemoteAhead
    );
    Ok(())
}

#[test]
fn divergence_is_still_detected_with_tombstones() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 300)],
    };
    let remote = SyncState {
        entries: vec![(
            "beta".to_string(),
            sample_entry(&crypto, "beta", "beta_pass", 250)?,
        )],
        tombstones: Vec::new(),
    };

    assert_eq!(
        SyncEngine::evaluate_status(&local, &remote, None, [1u8; 32], [2u8; 32]),
        SyncStatus::Diverged
    );
    Ok(())
}
