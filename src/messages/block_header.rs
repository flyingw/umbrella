use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::cmp::min;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::hash256::{sha256d, Hash256};
use crate::serdes::Serializable;

/// Block header
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct BlockHeader {
    /// Block version specifying which validation rules to use
    pub version: u32,
    /// Hash of the previous block
    pub prev_hash: Hash256,
    /// Root of the merkle tree of this block's transaction hashes
    pub merkle_root: Hash256,
    /// Timestamp when this block was created as recorded by the miner
    pub timestamp: u32,
    /// Target difficulty bits
    pub bits: u32,
    /// Nonce used to mine the block
    pub nonce: u32,
}

impl BlockHeader {
    /// Size of the BlockHeader in bytes
    pub const SIZE: usize = 80;

    /// Returns the size of the block header in bytes
    pub fn size(&self) -> usize {
        BlockHeader::SIZE
    }

    /// Calculates the hash for this block header
    pub fn hash(&self) -> Hash256 {
        let mut v = Vec::with_capacity(80);
        v.write_u32::<LittleEndian>(self.version).unwrap();
        self.prev_hash.write(&mut v).unwrap();
        self.merkle_root.write(&mut v).unwrap();
        v.write_u32::<LittleEndian>(self.timestamp).unwrap();
        v.write_u32::<LittleEndian>(self.bits).unwrap();
        v.write_u32::<LittleEndian>(self.nonce).unwrap();
        sha256d(&v)
    }

    /// Checks that the block header is valid
    pub fn validate(&self, hash: &Hash256, prev_headers: &[BlockHeader]) -> Result<()> {
        // Timestamp > median timestamp of last 11 blocks
        if prev_headers.len() > 0 {
            let h = &prev_headers[prev_headers.len() - min(prev_headers.len(), 11)..];
            let mut timestamps: Vec<u32> = h.iter().map(|x| x.timestamp).collect();
            timestamps.sort();
            if self.timestamp < timestamps[timestamps.len() / 2] {
                let msg = format!("Timestamp is too old: {}", self.timestamp);
                return Err(Error::BadData(msg));
            }
        }

        // POW
        let target = self.difficulty_target()?;
        if hash > &target {
            return Err(Error::BadData("Invalid POW".to_string()));
        }

        Ok(())
    }

    /// Calculates the target difficulty hash
    fn difficulty_target(&self) -> Result<Hash256> {
        let exp = (self.bits >> 24) as usize;
        if exp < 3 || exp > 32 {
            let msg = format!("Difficulty exponent out of range: {:?}", self.bits);
            return Err(Error::BadArgument(msg));
        }
        let mut difficulty = [0_u8; 32];
        difficulty[exp - 1] = ((self.bits >> 16) & 0xff) as u8;
        difficulty[exp - 2] = ((self.bits >> 08) & 0xff) as u8;
        difficulty[exp - 3] = ((self.bits >> 00) & 0xff) as u8;
        Ok(Hash256(difficulty))
    }
}

impl Serializable<BlockHeader> for BlockHeader {
    fn read(reader: &mut dyn Read) -> Result<BlockHeader> {
        let version = reader.read_u32::<LittleEndian>()?;
        let prev_hash = Hash256::read(reader)?;
        let merkle_root = Hash256::read(reader)?;
        let ts = reader.read_u32::<LittleEndian>()?;
        let bits = reader.read_u32::<LittleEndian>()?;
        let nonce = reader.read_u32::<LittleEndian>()?;
        Ok(BlockHeader {
            version,
            prev_hash,
            merkle_root,
            timestamp: ts,
            bits,
            nonce,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        self.prev_hash.write(writer)?;
        self.merkle_root.write(writer)?;
        writer.write_u32::<LittleEndian>(self.timestamp)?;
        writer.write_u32::<LittleEndian>(self.bits)?;
        writer.write_u32::<LittleEndian>(self.nonce)?;
        Ok(())
    }
}
