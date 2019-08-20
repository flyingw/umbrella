use std::cmp::min;

const LSHIFT_MASK: [u8; 8] = [0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01];
const RSHIFT_MASK: [u8; 8] = [0xff, 0xfE, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80];

/// Manages an array of bits
#[derive(Debug, Default, Clone)]
pub struct Bits {
    pub data: Vec<u8>,
    pub len: usize,
}

impl Bits {
    /// Creates an empty bit array
    pub fn new() -> Bits {
        Bits {
            data: vec![],
            len: 0,
        }
    }

    /// Creates a bits array with default capacity for a certain size
    pub fn with_capacity(capacity: usize) -> Bits {
        Bits {
            data: Vec::with_capacity(capacity / 8),
            len: 0,
        }
    }

    /// Creates the bits from a slice
    pub fn from_slice(data: &[u8], len: usize) -> Bits {
        let mut vec = data.to_vec();
        let len = min(data.len() * 8, len);
        if len > vec.len() * 8 {
            vec.truncate((len + 7) / 8);
        }
        let rem = (len % 8) as u8;
        if rem != 0 {
            let last = vec.len() - 1;
            vec[last] &= (!((1 << (8_u8 - rem)) - 1)) as u8;
        }
        Bits { data: vec, len }
    }

    /// Appends data to the bit array
    pub fn append(&mut self, other: &Bits) {
        let mut i = 0;
        while i < other.len / 8 {
            self.append_byte(other.data[i], 8);
            i += 1;
        }
        let rem = other.len % 8;
        if rem != 0 {
            self.append_byte(other.data[i], rem);
        }
    }

    /// Appends a byte or less to the bit array
    fn append_byte(&mut self, byte: u8, len: usize) {
        let end = self.len % 8;
        if end == 0 {
            self.data.push(byte);
            self.len += len;
        } else {
            let last = self.data.len() - 1;
            self.data[last] |= byte >> end;
            if len > 8 - end {
                self.data.push(byte << (8 - end));
            }
            self.len += len;
        }
    }

    /// Gets a range out of the bit array, right-aligned
    pub fn extract(&self, i: usize, len: usize) -> u64 {
        let end = i + len;
        let mut curr: u64 = 0;
        let mut i = i;
        for j in i / 8..((i + len + 7) / 8) {
            let b_len = min(end - i, 8 - (i - j * 8));
            curr = (curr << b_len) | self.extract_byte(i, b_len) as u64;
            i += b_len;
        }
        curr
    }

    /// Extracts a byte or less from the bit array, right-aligned
    pub fn extract_byte(&self, i: usize, len: usize) -> u8 {
        let b = (self.data[i / 8] >> (8 - (i % 8) - len)) as u16;
        (b & ((1_u16 << len) - 1)) as u8
    }
}

pub fn lshift(v: &[u8], n: usize) -> Vec<u8> {
    let bit_shift = n % 8;
    let byte_shift = (n / 8) as i32;

    let mask = LSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;

    let mut result = vec![0; v.len()];
    for i in (0..v.len()).rev() {
        let k = i as i32 - byte_shift;
        if k >= 0 {
            let mut val = v[i] & mask;
            val <<= bit_shift;
            result[k as usize] |= val;
        }
        if k - 1 >= 0 {
            let mut carryval = v[i] & overflow_mask;
            carryval >>= (8 - bit_shift) % 8;
            result[(k - 1) as usize] |= carryval;
        }
    }
    result
}

pub fn rshift(v: &[u8], n: usize) -> Vec<u8> {
    let bit_shift = n % 8;
    let byte_shift = n / 8;

    let mask = RSHIFT_MASK[bit_shift];
    let overflow_mask = !mask;

    let mut result = vec![0; v.len()];
    for i in 0..v.len() {
        let k = i + byte_shift;
        if k < v.len() {
            let mut val = v[i] & mask;
            val >>= bit_shift;
            result[k] |= val;
        }
        if k + 1 < v.len() {
            let mut carryval = v[i] & overflow_mask;
            carryval <<= (8 - bit_shift) % 8;
            result[k + 1] |= carryval;
        }
    }
    result
}
