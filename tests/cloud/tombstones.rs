use crate::support::sample_entry;
use cortex::cloud::engine::{MergeReport, SyncEngine, SyncState, SyncStatus};
use cortex::core::{crypto::Crypto, types::PasswordEntry};

use crate::common::TestResult;

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

fn into_state(report: MergeReport) -> SyncState {
    SyncState {
        entries: report.entries,
        tombstones: report.tombstones,
    }
}

#[test]
fn deletion_reaches_a_device_that_still_holds_the_entry() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let stale = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "alpha_pass", 100)?,
        )],
        tombstones: Vec::new(),
    };
    let deleted = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };

    let report = SyncEngine::merge(&stale, &crypto, &deleted, &crypto, true)?;
    assert_eq!(report.removed_from_remote, 1);
    assert!(report.entries.is_empty());
    assert_eq!(report.tombstones, vec![("alpha".to_string(), 200)]);
    Ok(())
}

#[test]
fn stale_device_cannot_resurrect_a_deleted_entry_across_repeated_merges() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let alpha = sample_entry(&crypto, "alpha", "alpha_pass", 100)?;
    let deleting_device = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };
    let relay = SyncState {
        entries: vec![("alpha".to_string(), alpha.clone())],
        tombstones: Vec::new(),
    };
    let stale = SyncState {
        entries: vec![("alpha".to_string(), alpha)],
        tombstones: Vec::new(),
    };

    let relay_after = into_state(SyncEngine::merge(
        &relay,
        &crypto,
        &deleting_device,
        &crypto,
        true,
    )?);
    assert!(relay_after.entries.is_empty());

    let stale_after = into_state(SyncEngine::merge(
        &stale,
        &crypto,
        &relay_after,
        &crypto,
        true,
    )?);
    assert!(stale_after.entries.is_empty());
    assert_eq!(stale_after.tombstones, vec![("alpha".to_string(), 200)]);

    let deleting_after = into_state(SyncEngine::merge(
        &deleting_device,
        &crypto,
        &stale_after,
        &crypto,
        true,
    )?);
    assert!(deleting_after.entries.is_empty());
    assert_eq!(deleting_after.tombstones, vec![("alpha".to_string(), 200)]);
    Ok(())
}

#[test]
fn concurrent_deletions_converge_to_the_later_tombstone() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let device_a = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };
    let device_b = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 250)],
    };

    let a_after = into_state(SyncEngine::merge(
        &device_a, &crypto, &device_b, &crypto, true,
    )?);
    let b_after = into_state(SyncEngine::merge(
        &device_b, &crypto, &device_a, &crypto, true,
    )?);

    assert_eq!(a_after.tombstones, vec![("alpha".to_string(), 250)]);
    assert_eq!(b_after.tombstones, vec![("alpha".to_string(), 250)]);
    assert!(a_after.entries.is_empty() && b_after.entries.is_empty());
    Ok(())
}

#[test]
fn entry_recreated_after_deletion_survives_repeated_merges() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let deleting_device = SyncState {
        entries: Vec::new(),
        tombstones: vec![("alpha".to_string(), 200)],
    };
    let recreating_device = SyncState {
        entries: vec![(
            "alpha".to_string(),
            sample_entry(&crypto, "alpha", "recreated_pass", 300)?,
        )],
        tombstones: Vec::new(),
    };

    let deleting_after = into_state(SyncEngine::merge(
        &deleting_device,
        &crypto,
        &recreating_device,
        &crypto,
        true,
    )?);
    assert_eq!(deleting_after.tombstones, Vec::new());
    assert_eq!(deleting_after.entries.len(), 1);

    let recreating_after = into_state(SyncEngine::merge(
        &recreating_device,
        &crypto,
        &deleting_after,
        &crypto,
        true,
    )?);
    assert_eq!(recreating_after.tombstones, Vec::new());
    let decrypted = crypto.decrypt_entry("alpha", &recreating_after.entries[0].1)?;
    assert_eq!(decrypted, b"recreated_pass");
    Ok(())
}
