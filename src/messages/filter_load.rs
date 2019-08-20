use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::var_int;
use crate::serdes::Serializable;
use crate::bloom_filter::BloomFilter;

/// Filter is not adjusted when a match is found
pub const BLOOM_UPDATE_NONE: u8 = 0;
/// Filter is updated to include the serialized outpoint if any data elements matched in its script pubkey
pub const BLOOM_UPDATE_ALL: u8 = 1;
/// Filter is updated simialr to BLOOM_UPDATE_ALL but only for P2PK or multisig transactions
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;

/// Loads a bloom filter using the specified parameters
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone)]
pub struct FilterLoad {
    /// Bloom filter
    pub bloom_filter: BloomFilter,
    /// Flags that control how matched items are added to the filter
    pub flags: u8,
}

impl FilterLoad {
    /// Returns whether the FilterLoad message is valid
    pub fn validate(&self) -> Result<()> {
        self.bloom_filter.validate()
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
            bloom_filter: BloomFilter {
                filter,
                num_hash_funcs,
                tweak,
            },
            flags,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.bloom_filter.filter.len() as u64, writer)?;
        writer.write(&self.bloom_filter.filter)?;
        writer.write_u32::<LittleEndian>(self.bloom_filter.num_hash_funcs as u32)?;
        writer.write_u32::<LittleEndian>(self.bloom_filter.tweak)?;
        writer.write_u8(self.flags)?;
        Ok(())
    }
}

impl Payload<FilterLoad> for FilterLoad {
    fn size(&self) -> usize {
        var_int::size(self.bloom_filter.filter.len() as u64) + self.bloom_filter.filter.len() + 9
    }
}
