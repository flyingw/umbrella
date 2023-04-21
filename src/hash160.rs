use hex;
use ring::digest::{digest, SHA256};
use ripemd::{Digest, Ripemd160};
use std::fmt;

/// 160-bit hash for public key addresses
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash160(pub [u8; 20]);

/// Hashes a data array once with SHA256 and again with RIPEMD160
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha256 = digest(&SHA256, data);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256.as_ref());
    let mut hash160 = [0; 20];
    hash160.clone_from_slice(&ripemd160.finalize());
    Hash160(hash160)
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
