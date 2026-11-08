use cortex::domain::limits::{THROTTLE_FREE_FAILURES, THROTTLE_MAX_DELAY_SECONDS};
use cortex::security::gateway::Gateway;

#[test]
fn throttle_allows_initial_free_attempts() {
    assert_eq!(Gateway::throttle_delay_seconds(0), 0);
    assert_eq!(Gateway::throttle_delay_seconds(1), 0);
    assert_eq!(Gateway::throttle_delay_seconds(2), 0);
}

#[test]
fn throttle_grows_exponentially_after_threshold() {
    assert_eq!(Gateway::throttle_delay_seconds(3), 1);
    assert_eq!(Gateway::throttle_delay_seconds(4), 2);
    assert_eq!(Gateway::throttle_delay_seconds(5), 4);
    assert_eq!(Gateway::throttle_delay_seconds(6), 8);
}

#[test]
fn throttle_caps_at_maximum_and_never_overflows() {
    assert_eq!(Gateway::throttle_delay_seconds(50), 3_600);
    assert_eq!(Gateway::throttle_delay_seconds(u32::MAX), 3_600);
}

#[test]
fn throttle_becomes_active_after_the_configured_free_failures() {
    assert_eq!(
        Gateway::throttle_delay_seconds(THROTTLE_FREE_FAILURES - 1),
        0
    );
    assert_eq!(Gateway::throttle_delay_seconds(THROTTLE_FREE_FAILURES), 1);
}

#[test]
fn throttle_never_decreases_as_failures_accumulate() {
    let mut previous = 0;
    for failures in 0..=200 {
        let delay = Gateway::throttle_delay_seconds(failures);
        assert!(delay >= previous, "failures={failures}");
        assert!(delay <= THROTTLE_MAX_DELAY_SECONDS);
        previous = delay;
    }
}

#[test]
fn throttle_doubles_until_it_reaches_the_cap() {
    for failures in THROTTLE_FREE_FAILURES..40 {
        let current = Gateway::throttle_delay_seconds(failures);
        let next = Gateway::throttle_delay_seconds(failures + 1);
        assert_eq!(
            next,
            (current * 2).min(THROTTLE_MAX_DELAY_SECONDS),
            "failures={failures}"
        );
    }
}
