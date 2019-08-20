use byteorder::{ReadBytesExt, WriteBytesExt};
use super::block_header::BlockHeader;
use super::message::Payload;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::hash256::Hash256;
use crate::result::{Error, Result};
use crate::serdes::Serializable;

/// Collection of block headers
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Headers {
    /// List of sequential block headers
    pub headers: Vec<BlockHeader>,
}

impl Serializable<Headers> for Headers {
    fn read(reader: &mut dyn Read) -> Result<Headers> {
        let n = var_int::read(reader)?;
        let mut headers = Vec::new();
        for _i in 0..n {
            headers.push(BlockHeader::read(reader)?);
            let _txn_count = reader.read_u8();
        }
        Ok(Headers { headers })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.headers.len() as u64, writer)?;
        for header in self.headers.iter() {
            header.write(writer)?;
            writer.write_u8(0)?;
        }
        Ok(())
    }
}

impl Payload<Headers> for Headers {
    fn size(&self) -> usize {
        var_int::size(self.headers.len() as u64) + (BlockHeader::SIZE + 1) * self.headers.len()
    }
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let h = format!("[<{} block headers>]", self.headers.len());
        f.debug_struct("Headers").field("headers", &h).finish()
    }
}

/// Returns the hash for a header at a particular index utilizing prev_hash if possible
pub fn header_hash(i: usize, headers: &Vec<BlockHeader>) -> Result<Hash256> {
    if i + 1 < headers.len() {
        return Ok(headers[i + 1].prev_hash);
    } else if i + 1 == headers.len() {
        return Ok(headers[i].hash());
    } else {
        return Err(Error::BadArgument("Index out of range".to_string()));
    }
}
