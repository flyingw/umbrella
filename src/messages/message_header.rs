use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::str;
use crate::result::{Error, Result};
use crate::serdes::Serializable;

/// Header that begins all messages
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MessageHeader {
    /// Magic bytes indicating the network type
    pub magic: [u8; 4],
    /// Command name
    pub command: [u8; 12],
    /// Payload size
    pub payload_size: u32,
    /// First 4 bytes of SHA256(SHA256(payload))
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Size of the message header in bytes
    pub const SIZE: usize = 24;

    /// Returns the size of the header in bytes
    pub fn size(&self) -> usize {
        MessageHeader::SIZE
    }

    /// Checks if the header is valid
    ///
    /// `magic` - Expected magic bytes for the network
    /// `max_size` - Max size in bytes for the payload
    pub fn validate(&self, magic: [u8; 4], max_size: u32) -> Result<()> {
        if self.magic != magic {
            let msg = format!("Bad magic: {:?}", self.magic);
            return Err(Error::BadData(msg));
        }
        if self.payload_size > max_size {
            let msg = format!("Bad size: {:?}", self.payload_size);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }

    /// Reads the payload and verifies its checksum
    pub fn payload(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut p = vec![0; self.payload_size as usize];
        reader.read_exact(p.as_mut())?;
        let hash = digest::digest(&digest::SHA256, p.as_ref());
        let hash = digest::digest(&digest::SHA256, &hash.as_ref());
        let h = &hash.as_ref();
        let j = &self.checksum;
        if h[0] != j[0] || h[1] != j[1] || h[2] != j[2] || h[3] != j[3] {
            let msg = format!("Bad checksum: {:?} != {:?}", &h[..4], j);
            return Err(Error::BadData(msg));
        }
        Ok(p)
    }
}

impl Serializable<MessageHeader> for MessageHeader {
    fn read(reader: &mut dyn Read) -> Result<MessageHeader> {
        // Read all the bytes at once so that the stream doesn't get in a partially-read state
        let mut p = vec![0; MessageHeader::SIZE];
        reader.read_exact(p.as_mut())?;
        let mut c = Cursor::new(p);

        // Now parse the results from the stream
        let mut ret = MessageHeader {
            ..Default::default()
        };
        c.read(&mut ret.magic)?;
        c.read(&mut ret.command)?;
        ret.payload_size = c.read_u32::<LittleEndian>()?;
        c.read(&mut ret.checksum)?;

        Ok(ret)
    }

    fn write(&mut self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write(&self.magic)?;
        writer.write(&self.command)?;
        writer.write_u32::<LittleEndian>(self.payload_size)?;
        writer.write(&self.checksum)?;
        Ok(())
    }
}

// Prints so the command is easier to read
impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = match str::from_utf8(&self.command) {
            Ok(s) => s.to_string(),
            Err(_) => format!("Not Ascii ({:?})", self.command),
        };
        write!(
            f,
            "Header {{ magic: {:?}, command: {:?}, payload_size: {}, checksum: {:?} }}",
            self.magic, command, self.payload_size, self.checksum
        )
    }
}
