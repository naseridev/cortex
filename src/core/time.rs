use std::time::{SystemTime, UNIX_EPOCH};

pub struct Time;

impl Time {
    #[must_use]
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}
