use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::var_int;
use crate::serdes::Serializable;

/// Filter is not adjusted when a match is found
pub const BLOOM_UPDATE_NONE: u8 = 0;
/// Filter is updated to include the serialized outpoint if any data elements matched in its script pubkey
pub const BLOOM_UPDATE_ALL: u8 = 1;
/// Filter is updated simialr to BLOOM_UPDATE_ALL but only for P2PK or multisig transactions
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;

/// Loads a bloom filter using the specified parameters
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FilterLoad {
    /// Flags that control how matched items are added to the filter
    pub flags: u8,
}

impl FilterLoad {
    /// Returns whether the FilterLoad message is valid
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl Serializable<FilterLoad> for FilterLoad {
    fn read(reader: &mut dyn Read) -> Result<FilterLoad> {
        let num_filters = var_int::read(reader)?;
        let mut filter = vec![0; num_filters as usize];
        reader.read(&mut filter)?;
        let num_hash_funcs = reader.read_u32::<LittleEndian>()? as usize;
        let tweak = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u8()?;
        Ok(FilterLoad {
            flags,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u8(self.flags)?;
        Ok(())
    }
}

impl Payload<FilterLoad> for FilterLoad {
    fn size(&self) -> usize {
    }
}
