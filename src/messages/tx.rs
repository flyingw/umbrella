use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use linked_hash_map::LinkedHashMap;
use super::message::Payload;
use super::out_point::{OutPoint,COINBASE_OUTPOINT_HASH, COINBASE_OUTPOINT_INDEX};
use super::tx_out::TxOut;
use super::tx_in::TxIn;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::hash256::{sha256d, Hash256};
use crate::result::{Error, Result};
use crate::serdes::Serializable;

/// Maximum number of satoshis possible
pub const MAX_SATOSHIS: i64 = 21_000_000 * 100_000_000;

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

    /// Validates a non-coinbase transaction
    pub fn validate(
        &self,
        utxos: &LinkedHashMap<OutPoint, TxOut>,
    ) -> Result<()> {
        // Make sure neither in or out lists are empty
        if self.inputs.len() == 0 {
            return Err(Error::BadData("inputs empty".to_string()));
        }
        if self.outputs.len() == 0 {
            return Err(Error::BadData("outputs empty".to_string()));
        }

        // Each output value, as well as the total, must be in legal money range
        let mut total_out = 0;
        for tx_out in self.outputs.iter() {
            if tx_out.amount.0 < 0 {
                return Err(Error::BadData("tx_out amount negative".to_string()));
            }
            total_out += tx_out.amount.0;
        }
        if total_out > MAX_SATOSHIS {
            return Err(Error::BadData("Total out exceeds max satoshis".to_string()));
        }

        // Make sure none of the inputs are coinbase transactions
        for tx_in in self.inputs.iter() {
            if tx_in.prev_output.hash == COINBASE_OUTPOINT_HASH
                && tx_in.prev_output.index == COINBASE_OUTPOINT_INDEX
            {
                return Err(Error::BadData("Unexpected coinbase".to_string()));
            }
        }

        // Check that lock_time <= INT_MAX because some clients interpret this differently
        if self.lock_time > 2_147_483_647 {
            return Err(Error::BadData("Lock time too large".to_string()));
        }

        // Check that all inputs are in the utxo set and are in legal money range
        let mut total_in = 0;
        for tx_in in self.inputs.iter() {
            let utxo = utxos.get(&tx_in.prev_output);
            if let Some(tx_out) = utxo {
                if tx_out.amount.0 < 0 {
                    return Err(Error::BadData("tx_out amount negative".to_string()));
                }
                total_in += tx_out.amount.0;
            } else {
                return Err(Error::BadData("utxo not found".to_string()));
            }
        }
        if total_in > MAX_SATOSHIS {
            return Err(Error::BadData("Total in exceeds max satoshis".to_string()));
        }

        // Check inputs spent > outputs received
        if total_in < total_out {
            return Err(Error::BadData("Output total exceeds input".to_string()));
        }

        Ok(())
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
