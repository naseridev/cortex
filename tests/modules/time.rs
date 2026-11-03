use cortex::modules::time::Time;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn current_timestamp_tracks_the_system_clock() {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let stamp = Time::current_timestamp();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();

    assert!((before..=after).contains(&stamp));
}
