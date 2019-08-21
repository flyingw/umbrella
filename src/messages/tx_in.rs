use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::out_point::OutPoint;
use crate::script::Script;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::result::Result;
use crate::serdes::Serializable;


/// Transaction input
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct TxIn {
    /// The previous output transaction reference
    pub prev_output: OutPoint,
    /// Signature script for confirming authorization
    pub sig_script: Script,
    /// Transaction version as defined by the sender for replacement or negotiation
    pub sequence: u32,
}

impl TxIn {
    /// Returns the size of the transaction input in bytes
    pub fn size(&self) -> usize {
        OutPoint::SIZE + var_int::size(self.sig_script.0.len() as u64) + self.sig_script.0.len() + 4
    }
}

impl Serializable<TxIn> for TxIn {
    fn read(reader: &mut dyn Read) -> Result<TxIn> {
        let prev_output = OutPoint::read(reader)?;
        let script_len = var_int::read(reader)?;
        let mut sig_script = Script(vec![0; script_len as usize]);
        reader.read(&mut sig_script.0)?;
        let sequence = reader.read_u32::<LittleEndian>()?;
        Ok(TxIn {
            prev_output,
            sig_script,
            sequence,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.prev_output.write(writer)?;
        var_int::write(self.sig_script.0.len() as u64, writer)?;
        writer.write(&self.sig_script.0)?;
        writer.write_u32::<LittleEndian>(self.sequence)?;
        Ok(())
    }
}
