use super::op_codes::*;

/// Gets the next operation index in the script, or the script length if at the end
pub fn next_op(i: usize, script: &[u8]) -> usize {
    if i >= script.len() {
        return script.len();
    }
    let next = match script[i] {
        len @ 1..=75 => i + 1 + len as usize,
        OP_PUSHDATA1 => {
            if i + 2 > script.len() {
                return script.len();
            }
            i + 2 + script[i + 1] as usize
        }
        OP_PUSHDATA2 => {
            if i + 3 > script.len() {
                return script.len();
            }
            i + 3 + ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8)
        }
        OP_PUSHDATA4 => {
            if i + 5 > script.len() {
                return script.len();
            }
            let len = ((script[i + 1] as usize) << 0)
                + ((script[i + 2] as usize) << 8)
                + ((script[i + 3] as usize) << 16)
                + ((script[i + 4] as usize) << 24);
            i + 5 + len
        }
        _ => i + 1,
    };
    let overflow = next > script.len();
    return if overflow { script.len() } else { next };
}
