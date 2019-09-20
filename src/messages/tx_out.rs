use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crate::script::Script;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::result::Result;
use crate::serdes::Serializable;
use crate::amount::Amount;
use crate::ctx::Ctx;

/// Transaction output
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TxOut {
    /// Number of satoshis to spend
    pub amount: Amount,
    /// Public key script to claim the output
    pub pk_script: Script,
}

impl TxOut {
    /// Returns the size of the transaction output in bytes
    pub fn size(&self) -> usize {
        8 + var_int::size(self.pk_script.0.len() as u64) + self.pk_script.0.len()
    }
}

impl Serializable<TxOut> for TxOut {
    fn read(reader: &mut dyn Read) -> Result<TxOut> {
        let amount = Amount(reader.read_i64::<LittleEndian>()?);
        let script_len = var_int::read(reader)?;
        let mut pk_script = Script(vec![0; script_len as usize]);
        reader.read(&mut pk_script.0)?;
        Ok(TxOut { amount, pk_script })
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write_i64::<LittleEndian>(self.amount.0)?;
        var_int::write(self.pk_script.0.len() as u64, writer)?;
        writer.write(&self.pk_script.0)?;
        Ok(())
    }
}
