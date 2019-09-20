use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use crate::ctx::Ctx;

/// Specifies whether compact blocks are supported
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct SendCmpct {
    /// Whether compact blocks may be sent
    pub enable: u8,
    /// Should always be 1
    pub version: u64,
}

impl SendCmpct {
    /// Size of the SendCmpct payload in bytes
    pub const SIZE: usize = 9;

    /// Returns whether compact blocks should be used
    pub fn use_cmpctblock(&self) -> bool {
        self.enable == 1 && self.version == 1
    }
}

impl Serializable<SendCmpct> for SendCmpct {
    fn read(reader: &mut dyn Read) -> Result<SendCmpct> {
        let enable = reader.read_u8()?;
        let version = reader.read_u64::<LittleEndian>()?;
        Ok(SendCmpct { enable, version })
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write_u8(self.enable)?;
        writer.write_u64::<LittleEndian>(self.version)
    }
}

impl Payload<SendCmpct> for SendCmpct {
    fn size(&self) -> usize {
        SendCmpct::SIZE
    }
}
