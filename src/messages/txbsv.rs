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
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::ctx::Ctx;

#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct TxBsv {
    pub key: String
    // pub txid: String
    // pub txindex: Int
    // pub amount: Int
    // pub msg: String
}

// impl TxBsv {
//     /// Calculates the hash of the transaction also known as the txid
//     pub fn hash(&mut self) -> Hash256 {
//         let mut b = Vec::with_capacity(self.size());
//         self.write(&mut b, &mut ()).unwrap();
//         sha256d(&b)
//     }

//     /// Returns whether the transaction is the block reward
//     pub fn coinbase(&self) -> bool {
//         return self.inputs.len() == 1
//             && self.inputs[0].prev_output.hash == COINBASE_OUTPOINT_HASH
//             && self.inputs[0].prev_output.index == COINBASE_OUTPOINT_INDEX;
//     }
// }

impl Serializable<TxBsv> for TxBsv {
    fn read(reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<TxBsv> {
        Err(Error::NotImplemented)
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(1)?;
        // var_int::write(self.inputs.len() as u64, writer)?;
        // for tx_in in self.inputs.iter() {
        //     tx_in.write(writer, ctx)?;
        // }
        // var_int::write(self.outputs.len() as u64, writer)?;
        // for tx_out in self.outputs.iter() {
        //     tx_out.write(writer, ctx)?;
        // }
        // writer.write_u32::<LittleEndian>(self.lock_time)?;
        Ok(())
    }
}

// key = "cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh"
// amount = 5000000000
// txid = "cec6ac057861ee3ad37fa39503b39057ada889578a2117bd775264d1a5289cfd"
// txindex = 0

// result
// 0100000001fd9c28a5d1645277bd17218a5789a8ad5790b30395a37fd33aee617805acc6ce000000006b48304502210090298a2bf23e5640396400e4afea95c872b7da1a90abba35da7aab3d1299627702206196a592a5a2d99f5dfba4830965e97ca5ae7359a1e72ae2f712dde60a80db9b41210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000005006a02686999f1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000

// impl Payload<TxBsv> for TxBsv {
//     fn size(&self) -> usize {
//         let mut size = 8;
//         size += var_int::size(self.inputs.len() as u64);
//         for tx_in in self.inputs.iter() {
//             size += tx_in.size();
//         }
//         size += var_int::size(self.outputs.len() as u64);
//         for tx_out in self.outputs.iter() {
//             size += tx_out.size();
//         }
//         size
//     }
// }

// impl fmt::Debug for TxBsv {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let inputs_str = format!("[<{} inputs>]", self.inputs.len());
//         let outputs_str = format!("[<{} outputs>]", self.outputs.len());

//         f.debug_struct("TxBsv")
//             .field("version", &self.version)
//             .field(
//                 "inputs",
//                 if self.inputs.len() <= 3 {
//                     &self.inputs
//                 } else {
//                     &inputs_str
//                 },
//             ).field(
//                 "outputs",
//                 if self.outputs.len() <= 3 {
//                     &self.outputs
//                 } else {
//                     &outputs_str
//                 },
//             ).field("lock_time", &self.lock_time)
//             .finish()
//     }
// }
