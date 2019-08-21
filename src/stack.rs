use crate::result::{Error, Result};

/// Converts a number to a 32-bit stack item
#[inline]
pub fn encode_num(val: i64) -> Result<Vec<u8>> {
    // Range: [-2^31+1, 2^31-1]
    if val > 2147483647 || val < -2147483647 {
        return Err(Error::ScriptError("Number out of range".to_string()));
    }
    let (posval, negmask) = if val < 0 { (-val, 128) } else { (val, 0) };
    if posval == 0 {
        Ok(vec![])
    } else if posval < 128 {
        Ok(vec![(posval as u8) | negmask])
    } else if posval < 32768 {
        Ok(vec![(posval >> 0) as u8, ((posval >> 8) as u8) | negmask])
    } else if posval < 8388608 {
        Ok(vec![
            (posval >> 0) as u8,
            (posval >> 8) as u8,
            ((posval >> 16) as u8) | negmask,
        ])
    } else {
        Ok(vec![
            (posval >> 0) as u8,
            (posval >> 8) as u8,
            (posval >> 16) as u8,
            ((posval >> 24) as u8) | negmask,
        ])
    }
}
