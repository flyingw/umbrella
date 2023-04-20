use hex;
use ring::digest::{digest, SHA256};
use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use super::result::{Error, Result};
use super::serdes::Serializable;
use rand;
use rand::RngCore;
use std::ops::{Index};
use core::slice::SliceIndex;
use core::ops::{BitXor, BitXorAssign};
use super::ctx::Ctx;

/// 256-bit hash for blocks and transactions
///
/// It is interpreted as a single little-endian number for display.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Converts the hash into a hex string
    pub fn encode(&self) -> String {
        let mut r = self.0.clone();
        r.reverse();
        hex::encode(r)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn random() -> Self {
        let mut res = Self::default();
        use rand_core::OsRng;
        OsRng.fill_bytes(res.as_bytes_mut());
        res
    }

    pub fn from_slice(d: &[u8]) -> Self {
        assert_eq!(32, d.len());
        let mut hash = Hash256::default();
        hash.as_bytes_mut().copy_from_slice(d);
        hash
    }

    pub fn copy_from_slice(&mut self, d: &[u8]) {
      assert_eq!(32, d.len());
      self.as_bytes_mut().copy_from_slice(d);
    }

    /// Converts a string of 64 hex characters into a hash
    pub fn decode(s: &str) -> Result<Hash256> {
        let decoded_bytes = hex::decode(s)?;
        let mut hash_bytes = [0; 32];
        if decoded_bytes.len() != 32 {
            let msg = format!("Length {} of {:?}", decoded_bytes.len(), decoded_bytes);
            return Err(Error::BadArgument(msg));
        }
        hash_bytes.clone_from_slice(&decoded_bytes);
        hash_bytes.reverse();
        Ok(Hash256(hash_bytes))
    }
}

impl Serializable<Hash256> for Hash256 {
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Hash256> {
        let mut bytes = [0; 32];
        reader.read(&mut bytes)?;
        Ok(Hash256(bytes))
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        match writer.write(&self.0) {
            Ok(_size) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Hashes a data array twice using SHA256
pub fn sha256d(data: &[u8]) -> Hash256 {
    let sha256 = digest(&SHA256, &data);
    let sha256d = digest(&SHA256, sha256.as_ref());
    let mut hash256 = [0; 32];
    hash256.clone_from_slice(sha256d.as_ref());
    Hash256(hash256)
}

impl Ord for Hash256 {
    fn cmp(&self, other: &Hash256) -> Ordering {
        for i in (0..32).rev() {
            if self.0[i] < other.0[i] {
                return Ordering::Less;
            } else if self.0[i] > other.0[i] {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Hash256 {
    fn partial_cmp(&self, other: &Hash256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl<I> Index<I> for Hash256 where I: SliceIndex<[u8]> {
  type Output = I::Output;

  #[inline]
  fn index(&self, index: I) -> &I::Output {
    &self.as_bytes()[index]
  }
}

impl BitXor for Hash256 {
  type Output = Hash256;

  fn bitxor(self, x2: Hash256) -> Self::Output {
    let mut x1 = self.clone();
    x1 ^= x2;
    x1
  }
}

impl BitXorAssign for Hash256 {
  fn bitxor_assign(&mut self, x2: Hash256) {
    for (x1, x2) in self.as_bytes_mut().iter_mut().zip(x2.as_bytes()) {
      *x1 ^= x2;
    }
  }
}
