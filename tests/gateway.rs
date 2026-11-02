use cortex::modules::gateway::throttle_delay_seconds;

#[test]
fn throttle_allows_initial_free_attempts() {
    assert_eq!(throttle_delay_seconds(0), 0);
    assert_eq!(throttle_delay_seconds(1), 0);
    assert_eq!(throttle_delay_seconds(2), 0);
}

#[test]
fn throttle_grows_exponentially_after_threshold() {
    assert_eq!(throttle_delay_seconds(3), 1);
    assert_eq!(throttle_delay_seconds(4), 2);
    assert_eq!(throttle_delay_seconds(5), 4);
    assert_eq!(throttle_delay_seconds(6), 8);
}

#[test]
fn throttle_caps_at_maximum_and_never_overflows() {
    assert_eq!(throttle_delay_seconds(50), 3_600);
    assert_eq!(throttle_delay_seconds(u32::MAX), 3_600);
}