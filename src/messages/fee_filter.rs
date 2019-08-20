use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use crate::serdes::Serializable;
use crate::result::Result;

/// Specifies the minimum transaction fee this node accepts
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct FeeFilter {
    /// Minimum fee accepted by the node in sats/1000 bytes
    pub minfee: u64,
}

impl FeeFilter {
    /// Size of the fee filter payload in bytes
    pub const SIZE: usize = 8;
}

impl Serializable<FeeFilter> for FeeFilter {
    fn read(reader: &mut dyn Read) -> Result<FeeFilter> {
        let minfee = reader.read_u64::<LittleEndian>()?;
        Ok(FeeFilter { minfee })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.minfee)
    }
}

impl Payload<FeeFilter> for FeeFilter {
    fn size(&self) -> usize {
        FeeFilter::SIZE
    }
}
