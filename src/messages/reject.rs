use byteorder::{ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use crate::var_int;
use crate::hash256::Hash256;
use crate::result::{Error, Result};
use crate::serdes::Serializable;


/// Message rejection error codes
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RejectCode {
    RejectMalformed = 0x01,
    RejectInvalid = 0x10,
    RejectObsolete = 0x11,
    RejectDuplicate = 0x12,
    RejectNonstandard = 0x40,
    RejectDust = 0x41,
    RejectInsufficientFee = 0x42,
    RejectCheckpoint = 0x43,
}

impl RejectCode {
    /// Converts an integer to a reject code
    pub fn from_u8(x: u8) -> Result<RejectCode> {
        match x {
            x if x == RejectCode::RejectMalformed as u8 => Ok(RejectCode::RejectMalformed),
            x if x == RejectCode::RejectInvalid as u8 => Ok(RejectCode::RejectInvalid),
            x if x == RejectCode::RejectObsolete as u8 => Ok(RejectCode::RejectObsolete),
            x if x == RejectCode::RejectDuplicate as u8 => Ok(RejectCode::RejectDuplicate),
            x if x == RejectCode::RejectNonstandard as u8 => Ok(RejectCode::RejectNonstandard),
            x if x == RejectCode::RejectDust as u8 => Ok(RejectCode::RejectDust),
            x if x == RejectCode::RejectInsufficientFee as u8 => {
                Ok(RejectCode::RejectInsufficientFee)
            }
            x if x == RejectCode::RejectCheckpoint as u8 => Ok(RejectCode::RejectCheckpoint),
            _ => {
                let msg = format!("Unknown rejection code: {}", x);
                Err(Error::BadArgument(msg))
            }
        }
    }
}

/// Rejected message
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Reject {
    /// Type of message rejected
    pub message: String,
    /// Error code
    pub code: RejectCode,
    /// Reason for rejection
    pub reason: String,
    /// Optional extra data that may be present for some rejections
    ///
    /// Currently this is only a 32-byte hash of the block or transaction if applicable.
    pub data: Vec<u8>,
}

impl Serializable<Reject> for Reject {
    fn read(reader: &mut dyn Read) -> Result<Reject> {
        let message_size = var_int::read(reader)? as usize;
        let mut message_bytes = vec![0; message_size];
        reader.read(&mut message_bytes)?;
        let message = String::from_utf8(message_bytes)?;
        let code = RejectCode::from_u8(reader.read_u8()?)?;
        let reason_size = var_int::read(reader)? as usize;
        let mut reason_bytes = vec![0; reason_size];
        reader.read(&mut reason_bytes)?;
        let reason = String::from_utf8(reason_bytes)?;
        let mut data = vec![];
        if message == "block".to_string() || message == "tx".to_string() {
            data = vec![0_u8; 32];
            reader.read(&mut data)?;
        }
        Ok(Reject {
            message,
            code,
            reason,
            data,
        })
    }

    fn write(&mut self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.message.as_bytes().len() as u64, writer)?;
        writer.write(&self.message.as_bytes())?;
        writer.write_u8(self.code as u8)?;
        var_int::write(self.reason.as_bytes().len() as u64, writer)?;
        writer.write(&self.reason.as_bytes())?;
        writer.write(&self.data)?;
        Ok(())
    }
}

impl Payload<Reject> for Reject {
    fn size(&self) -> usize {
        var_int::size(self.message.as_bytes().len() as u64)
            + self.message.as_bytes().len()
            + 1
            + var_int::size(self.reason.as_bytes().len() as u64)
            + self.reason.as_bytes().len()
            + self.data.len()
    }
}

impl fmt::Debug for Reject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data_str = "".to_string();
        if self.message == "block".to_string() || self.message == "tx".to_string() {
            let mut data = Cursor::new(&self.data);
            data_str = Hash256::read(&mut data).unwrap().encode();
        }
        f.debug_struct("Reject")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("reason", &self.reason)
            .field("data", &data_str)
            .finish()
    }
}
