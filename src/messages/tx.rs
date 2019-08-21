use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use super::out_point::{COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
use super::tx_out::TxOut;
use super::tx_in::TxIn;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::hash256::{sha256d, Hash256};
use crate::result::Result;
use crate::serdes::Serializable;

/// Bitcoin transaction
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Tx {
    /// Transaction version
    pub version: u32,
    /// Transaction inputs
    pub inputs: Vec<TxIn>,
    /// Transaction outputs
    pub outputs: Vec<TxOut>,
    /// The block number or timestamp at which this transaction is unlocked
    pub lock_time: u32,
}

impl Tx {
    /// Calculates the hash of the transaction also known as the txid
    pub fn hash(&self) -> Hash256 {
        let mut b = Vec::with_capacity(self.size());
        self.write(&mut b).unwrap();
        sha256d(&b)
    }

    /// Returns whether the transaction is the block reward
    pub fn coinbase(&self) -> bool {
        return self.inputs.len() == 1
            && self.inputs[0].prev_output.hash == COINBASE_OUTPOINT_HASH
            && self.inputs[0].prev_output.index == COINBASE_OUTPOINT_INDEX;
    }
}

impl Serializable<Tx> for Tx {
    fn read(reader: &mut dyn Read) -> Result<Tx> {
        let version = reader.read_i32::<LittleEndian>()?;
        let version = version as u32;
        let n_inputs = var_int::read(reader)?;
        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _i in 0..n_inputs {
            inputs.push(TxIn::read(reader)?);
        }
        let n_outputs = var_int::read(reader)?;
        let mut outputs = Vec::with_capacity(n_outputs as usize);
        for _i in 0..n_outputs {
            outputs.push(TxOut::read(reader)?);
        }
        let lock_time = reader.read_u32::<LittleEndian>()?;
        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        var_int::write(self.inputs.len() as u64, writer)?;
        for tx_in in self.inputs.iter() {
            tx_in.write(writer)?;
        }
        var_int::write(self.outputs.len() as u64, writer)?;
        for tx_out in self.outputs.iter() {
            tx_out.write(writer)?;
        }
        writer.write_u32::<LittleEndian>(self.lock_time)?;
        Ok(())
    }
}

impl Payload<Tx> for Tx {
    fn size(&self) -> usize {
        let mut size = 8;
        size += var_int::size(self.inputs.len() as u64);
        for tx_in in self.inputs.iter() {
            size += tx_in.size();
        }
        size += var_int::size(self.outputs.len() as u64);
        for tx_out in self.outputs.iter() {
            size += tx_out.size();
        }
        size
    }
}

impl fmt::Debug for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inputs_str = format!("[<{} inputs>]", self.inputs.len());
        let outputs_str = format!("[<{} outputs>]", self.outputs.len());

        f.debug_struct("Tx")
            .field("version", &self.version)
            .field(
                "inputs",
                if self.inputs.len() <= 3 {
                    &self.inputs
                } else {
                    &inputs_str
                },
            ).field(
                "outputs",
                if self.outputs.len() <= 3 {
                    &self.outputs
                } else {
                    &outputs_str
                },
            ).field("lock_time", &self.lock_time)
            .finish()
    }
}
