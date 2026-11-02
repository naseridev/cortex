use cortex::modules::gateway::throttle_delay_seconds;

#[test]
fn no_delay_within_free_failures() {
    assert_eq!(throttle_delay_seconds(0), 0);
    assert_eq!(throttle_delay_seconds(2), 0);
}

#[test]
fn delay_doubles_after_free_failures() {
    assert_eq!(throttle_delay_seconds(3), 1);
    assert_eq!(throttle_delay_seconds(4), 2);
    assert_eq!(throttle_delay_seconds(5), 4);
}

#[test]
fn delay_is_capped_and_never_overflows() {
    assert_eq!(throttle_delay_seconds(u32::MAX), 3_600);
    assert_eq!(throttle_delay_seconds(100), 3_600);
}
