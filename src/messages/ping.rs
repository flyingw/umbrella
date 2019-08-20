use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;


/// Ping or pong payload
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Ping {
    /// Unique identifier nonce
    pub nonce: u64,
}

impl Ping {
    /// Size of the ping or pong payload in bytes
    pub const SIZE: usize = 8;
}

impl Serializable<Ping> for Ping {
    fn read(reader: &mut dyn Read) -> Result<Ping> {
        let nonce = reader.read_u64::<LittleEndian>()?;
        Ok(Ping { nonce })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.nonce)
    }
}

impl Payload<Ping> for Ping {
    fn size(&self) -> usize {
        Ping::SIZE
    }
}
