use cortex::system::time::Time;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn current_timestamp_tracks_the_system_clock() -> Result<(), Box<dyn std::error::Error>> {
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let stamp = Time::current_timestamp();
    let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    assert!((before..=after).contains(&stamp));
    Ok(())
}
