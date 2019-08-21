//! Miscellaneous helpers

use std::time::SystemTime;

/// Gets the time in seconds since a time in the past
pub fn secs_since(time: SystemTime) -> u32 {
    SystemTime::now().duration_since(time).unwrap().as_secs() as u32
}
