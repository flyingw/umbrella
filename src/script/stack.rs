use crate::result::{Error, Result};

/// Pops a bool off the stack
#[inline]
pub fn pop_bool(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    if stack.len() == 0 {
        let msg = "Cannot pop bool, empty stack".to_string();
        return Err(Error::ScriptError(msg));
    }
    let top = stack.pop().unwrap();
    // Bools cannot be popped having more than 32-bits, but may be used in other ways
    if top.len() > 4 {
        let msg = format!("Cannot pop bool, len too long {}", top.len());
        return Err(Error::ScriptError(msg));
    }
    Ok(decode_bool(&top))
}

/// Pops a number off the stack
#[inline]
pub fn pop_num(stack: &mut Vec<Vec<u8>>) -> Result<i32> {
    if stack.len() == 0 {
        let msg = "Cannot pop num, empty stack".to_string();
        return Err(Error::ScriptError(msg));
    }
    let top = stack.pop().unwrap();
    // Numbers cannot be popped having more than 4 bytes, but may overflow on the stack to 5 bytes
    // after certain operations and may be used as byte vectors.
    if top.len() > 4 {
        let msg = format!("Cannot pop num, len too long {}", top.len());
        return Err(Error::ScriptError(msg));
    }
    Ok(decode_num(&top)? as i32)
}

/// Converts a stack item to a bool
#[inline]
pub fn decode_bool(s: &[u8]) -> bool {
    if s.len() == 0 {
        return false;
    }
    for i in 0..s.len() - 1 {
        if s[i] != 0 {
            return true;
        }
    }
    s[s.len() - 1] & 127 != 0
}

/// Converts a stack item to a number
#[inline]
pub fn decode_num(s: &[u8]) -> Result<i64> {
    let mut val = match s.len() {
        0 => return Ok(0),
        1 => (s[0] & 127) as i64,
        2 => (((s[1] & 127) as i64) << 8) + ((s[0] as i64) << 0),
        3 => (((s[2] & 127) as i64) << 16) + ((s[1] as i64) << 8) + ((s[0] as i64) << 0),
        4 => {
            (((s[3] & 127) as i64) << 24)
                + ((s[2] as i64) << 16)
                + ((s[1] as i64) << 8)
                + ((s[0] as i64) << 0)
        }
        _ => {
            for i in 4..s.len() - 1 {
                if s[i] != 0 {
                    return Err(Error::ScriptError("Number too big".to_string()));
                }
            }
            if s[s.len() - 1] & 127 != 0 {
                return Err(Error::ScriptError("Number too big".to_string()));
            }
            ((s[3] as i64) << 24)
                + ((s[2] as i64) << 16)
                + ((s[1] as i64) << 8)
                + ((s[0] as i64) << 0)
        }
    };
    if s[s.len() - 1] & 128 != 0 {
        val = 0 - val;
    }
    Ok(val)
}

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

/// Converts a number to a stack item, allowing for overflow to 5 bytes
#[inline]
pub fn encode_num_overflow(val: i64) -> Result<Vec<u8>> {
    // Range: [-2^31+1 -2^31+1, 2^31-1 + 2^31-1]
    if val > 4294967294 || val < -4294967294 {
        return Err(Error::ScriptError("Number out of range".to_string()));
    }
    let (posval, negmask) = if val < 0 { (-val, 128) } else { (val, 0) };
    if posval <= 2147483647 {
        encode_num(val)
    } else {
        Ok(vec![
            (posval >> 0) as u8,
            (posval >> 8) as u8,
            (posval >> 16) as u8,
            (posval >> 24) as u8,
            ((posval >> 32) as u8) | negmask,
        ])
    }
}
