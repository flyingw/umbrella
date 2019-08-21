use linked_hash_map::LinkedHashMap;
use super::message::Payload;
use super::out_point::OutPoint;
use super::tx::Tx;
use super::tx_out::TxOut;
use std::collections::{HashSet};
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::var_int;
use crate::serdes::Serializable;

/// Block of transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Block {
    /// Block transactions
    pub txns: Vec<Tx>,
}

impl Block {
    /// Returns a set of the inputs spent in this block
    pub fn inputs(&self) -> Result<HashSet<OutPoint>> {
        let mut inputs = HashSet::new();
        for txn in self.txns.iter() {
            if !txn.coinbase() {
                for input in txn.inputs.iter() {
                    if inputs.contains(&input.prev_output) {
                        let msg = "Input double spent".to_string();
                        return Err(Error::BadData(msg));
                    }
                    inputs.insert(input.prev_output.clone());
                }
            }
        }
        Ok(inputs)
    }

    /// Returns a map of the new outputs generated from this block including those spent within the block
    pub fn outputs(&self) -> Result<LinkedHashMap<OutPoint, TxOut>> {
        let mut outputs = LinkedHashMap::new();
        for txn in self.txns.iter() {
            let hash = txn.hash();
            for index in 0..txn.outputs.len() as u32 {
                outputs.insert(
                    OutPoint { hash, index },
                    txn.outputs[index as usize].clone(),
                );
            }
        }
        Ok(outputs)
    }
}

impl Serializable<Block> for Block {
    fn read(reader: &mut dyn Read) -> Result<Block> {
        let txn_count = var_int::read(reader)?;
        let mut txns = Vec::with_capacity(txn_count as usize);
        for _i in 0..txn_count {
            txns.push(Tx::read(reader)?);
        }
        Ok(Block { txns })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.txns.len() as u64, writer)?;
        for txn in self.txns.iter() {
            txn.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Block> for Block {
    fn size(&self) -> usize {
        0
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.txns.len() <= 3 {
            f.debug_struct("Block")
                .field("txns", &self.txns)
                .finish()
        } else {
            let txns = format!("[<{} transactions>]", self.txns.len());
            f.debug_struct("Block")
                .field("txns", &txns)
                .finish()
        }
    }
}
