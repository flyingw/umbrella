use linked_hash_map::LinkedHashMap;
use super::message::Payload;
use super::out_point::OutPoint;
use super::tx::Tx;
use super::tx_out::TxOut;
use super::block_header::BlockHeader;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::var_int;
use crate::serdes::Serializable;
use crate::hash256::{Hash256,sha256d};

/// Block height that Bitcoin Cash forked from BTC
pub const BITCOIN_CASH_FORK_HEIGHT: i32 = 478558;

/// Block of transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
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

    /// Checks that the block is valid
    pub fn validate(&self, height: i32, utxos: &LinkedHashMap<OutPoint, TxOut>) -> Result<()> {
        if self.txns.len() == 0 {
            return Err(Error::BadData("Txn count is zero".to_string()));
        }

        if self.merkle_root() != self.header.merkle_root {
            return Err(Error::BadData("Bad merkle root".to_string()));
        }

        let mut has_coinbase = false;
        let require_sighash_forkid = height >= BITCOIN_CASH_FORK_HEIGHT;
        for txn in self.txns.iter() {
            if !txn.coinbase() {
                txn.validate(require_sighash_forkid, utxos)?;
            } else if has_coinbase {
                return Err(Error::BadData("Multiple coinbases".to_string()));
            } else {
                has_coinbase = true;
            }
        }
        if !has_coinbase {
            return Err(Error::BadData("No coinbase".to_string()));
        }

        Ok(())
    }

    /// Calculates the merkle root from the transactions
    fn merkle_root(&self) -> Hash256 {
        let mut row = VecDeque::new();
        for tx in self.txns.iter() {
            row.push_back(tx.hash());
        }
        while row.len() > 1 {
            let mut n = row.len();
            while n > 0 {
                n -= 1;
                let h1 = row.pop_front().unwrap();
                let h2 = if n == 0 {
                    h1.clone()
                } else {
                    n -= 1;
                    row.pop_front().unwrap()
                };
                let mut h = Vec::with_capacity(64);
                h1.write(&mut h).unwrap();
                h2.write(&mut h).unwrap();
                row.push_back(sha256d(&h));
            }
        }
        return row.pop_front().unwrap();
    }
}

impl Serializable<Block> for Block {
    fn read(reader: &mut dyn Read) -> Result<Block> {
        let header = BlockHeader::read(reader)?;
        let txn_count = var_int::read(reader)?;
        let mut txns = Vec::with_capacity(txn_count as usize);
        for _i in 0..txn_count {
            txns.push(Tx::read(reader)?);
        }
        Ok(Block { header, txns })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        var_int::write(self.txns.len() as u64, writer)?;
        for txn in self.txns.iter() {
            txn.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Block> for Block {
    fn size(&self) -> usize {
        let mut size = BlockHeader::SIZE;
        size += var_int::size(self.txns.len() as u64);
        for txn in self.txns.iter() {
            size += txn.size();
        }
        size
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.txns.len() <= 3 {
            f.debug_struct("Block")
                .field("header", &self.header)
                .field("txns", &self.txns)
                .finish()
        } else {
            let txns = format!("[<{} transactions>]", self.txns.len());
            f.debug_struct("Block")
                .field("header", &self.header)
                .field("txns", &txns)
                .finish()
        }
    }
}
