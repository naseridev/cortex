use std::time::{SystemTime, UNIX_EPOCH};

pub struct Time;

impl Time {
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
