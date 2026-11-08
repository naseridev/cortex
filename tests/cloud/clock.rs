use crate::support::sample_entry;
use cortex::cloud::engine::{CLOCK_SKEW_TOLERANCE_SECS, ClockSkew, SyncEngine, SyncState};
use cortex::security::crypto::Crypto;

use crate::common::TestResult;

#[test]
fn skew_reports_remote_clock_ahead_of_this_device() {
    let skew = SyncEngine::clock_skew(5_000, 0, 1_000);
    assert_eq!(
        skew,
        ClockSkew {
            remote_ahead_secs: 4_000,
            vault_ahead_secs: 0,
        }
    );
    assert!(skew.remote_exceeds_tolerance());
}

#[test]
fn skew_within_tolerance_is_not_flagged() {
    let skew = SyncEngine::clock_skew(1_000 + CLOCK_SKEW_TOLERANCE_SECS, 0, 1_000);
    assert_eq!(skew.remote_ahead_secs, CLOCK_SKEW_TOLERANCE_SECS);
    assert!(!skew.remote_exceeds_tolerance());
}

#[test]
fn local_vault_clock_ahead_of_this_device_is_flagged() {
    let skew = SyncEngine::clock_skew(0, 5_000, 1_000);
    assert_eq!(skew.vault_ahead_secs, 4_000);
    assert!(skew.vault_exceeds_tolerance());
    assert!(!skew.remote_exceeds_tolerance());
}

#[test]
fn merge_clock_covers_every_winning_timestamp() -> TestResult {
    let crypto = Crypto::from_key([3u8; 32]);
    let local = SyncState {
        entries: vec![(
            "beta".to_string(),
            sample_entry(&crypto, "beta", "beta_pass", 100)?,
        )],
        tombstones: vec![("alpha".to_string(), 900)],
    };
    let remote = SyncState {
        entries: vec![
            (
                "alpha".to_string(),
                sample_entry(&crypto, "alpha", "alpha_pass", 700)?,
            ),
            (
                "gamma".to_string(),
                sample_entry(&crypto, "gamma", "gamma_pass", 1_200)?,
            ),
        ],
        tombstones: Vec::new(),
    };

    let report = SyncEngine::merge(&local, &crypto, &remote, &crypto, true)?;
    assert_eq!(report.clock, 1_200);
    Ok(())
}
