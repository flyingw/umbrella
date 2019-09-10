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
        use rand::distributions::Distribution;
        let mut res = Self::default();
        let mut rng = rand::rngs::EntropyRng::new();
        rng.fill_bytes(res.as_bytes_mut());
        res
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
    fn read(reader: &mut dyn Read) -> Result<Hash256> {
        let mut bytes = [0; 32];
        reader.read(&mut bytes)?;
        Ok(Hash256(bytes))
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
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
