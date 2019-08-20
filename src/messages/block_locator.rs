use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use super::version::MIN_SUPPORTED_PROTOCOL_VERSION;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::hash256::Hash256;
use crate::var_int;
use crate::serdes::Serializable;

/// Return results until either there are 2000 for getheaders or 500 or getblocks, or no more left
pub const NO_HASH_STOP: Hash256 = Hash256([0; 32]);

/// Specifies which blocks to return
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct BlockLocator {
    /// Protocol version of this node
    pub version: u32,
    /// Block hash to start after. First found will be used.
    pub block_locator_hashes: Vec<Hash256>,
    /// Block hash to stop at, or none if NO_HASH_STOP.
    pub hash_stop: Hash256,
}

impl BlockLocator {
    /// Checks if the message is valid
    pub fn validate(&self) -> Result<()> {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION as u32 {
            let msg = format!("Unsupported protocol version: {}", self.version);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }
}

impl Serializable<BlockLocator> for BlockLocator {
    fn read(reader: &mut dyn Read) -> Result<BlockLocator> {
        let version = reader.read_u32::<LittleEndian>()?;
        let num_hashes = var_int::read(reader)?;
        let mut block_locator_hashes = Vec::new();
        for _i in 0..num_hashes {
            block_locator_hashes.push(Hash256::read(reader)?);
        }
        let hash_stop = Hash256::read(reader)?;
        Ok(BlockLocator {
            version,
            block_locator_hashes,
            hash_stop,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        var_int::write(self.block_locator_hashes.len() as u64, writer)?;
        for hash in self.block_locator_hashes.iter() {
            hash.write(writer)?;
        }
        self.hash_stop.write(writer)?;
        Ok(())
    }
}

impl Payload<BlockLocator> for BlockLocator {
    fn size(&self) -> usize {
        4 + var_int::size(self.block_locator_hashes.len() as u64)
            + self.block_locator_hashes.len() * 32
            + 32
    }
}