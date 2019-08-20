//! Miscellaneous helpers

use std::time::SystemTime;

#[allow(dead_code)]
pub use super::bloom_filter::{
    BloomFilter, BLOOM_FILTER_MAX_FILTER_SIZE, BLOOM_FILTER_MAX_HASH_FUNCS,
};

/// Gets the time in seconds since a time in the past
pub fn secs_since(time: SystemTime) -> u32 {
    SystemTime::now().duration_since(time).unwrap().as_secs() as u32
}
