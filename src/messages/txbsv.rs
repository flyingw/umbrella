use byteorder::{LittleEndian, WriteBytesExt};
use crate::ctx::Ctx;
use crate::double_sha256;
use crate::key_scriptcode;
use crate::Output;
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::var_int;
use crate::{SIGHASH_ALL, SIGHASH_FORKID};
use rust_base58::FromBase58;
use secp256k1::SecretKey;
use secp256k1::{Message, Secp256k1};
use std::io::Cursor;
use std::io::{Read, Write};
use std::io;

// #[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct UnspentBsv {
    pub txid: Vec<u8>,
    pub txindex: u32,
    pub amount: u64,
}

// pub const OP_DUP: u8 = 118;
// pub const OP_HASH160: u8 = 169;
// pub const OP_PUSH_20: u8 = 0x14;
// pub const OP_EQUALVERIFY: u8 = 136;
// pub const OP_CHECKSIG: u8 = 172;

// #[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct TxBsv {
    // pub key: String,
    pub unspents: Vec<UnspentBsv>,
    // pub msg: String
    pub outputs: Vec<Output>,
    pub private_key: Vec<u8>,
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

pub struct TxInBsv {
    pub txid: Vec<u8>,
    pub txindex: u32,
    pub amount: u64,
    //script
    //script_len
}

impl Serializable<TxBsv> for TxBsv {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<TxBsv> {
        Err(Error::NotImplemented)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(1)?;
        var_int::write(self.unspents.len() as u64, writer)?;
        
        let mut is = Cursor::new(Vec::new());
        for tx_out in self.outputs.iter() {
            tx_out.write(&mut is, &mut ()).unwrap();
        }
        let hash_outputs = double_sha256(is.get_ref());

        let mut inputs = Vec::new();
        for unspent in self.unspents.iter() {
            let mut txid = hex::decode(&unspent.txid).unwrap();
            txid.reverse();
            inputs.push(TxInBsv{
                txid: txid,
                txindex: unspent.txindex,
                amount: unspent.amount,
            });
        }

        let mut hash_prevouts1 = Cursor::new(Vec::new());
        for tx_in in inputs.iter() {
            hash_prevouts1.write(&tx_in.txid)?;
            hash_prevouts1.write_u32::<LittleEndian>(tx_in.txindex)?;
        }
        let hash_prevouts = double_sha256(&hash_prevouts1.get_ref());

        let mut hash_sequence1 = Cursor::new(Vec::new());
        for _ in inputs.iter() {
            hash_sequence1.write_u32::<LittleEndian>(0xffffffff)?;
        }
        let hash_sequence = double_sha256(&hash_sequence1.get_ref());

        // let mut inputScripts = Vec::new();
        for tx_in in inputs.iter() {
            let mut to_be_hashed = Cursor::new(Vec::new());
            to_be_hashed.write_u32::<LittleEndian>(1)?;
            to_be_hashed.write(&hash_prevouts)?;
            to_be_hashed.write(&hash_sequence)?;
            to_be_hashed.write(&tx_in.txid)?;
            to_be_hashed.write_u32::<LittleEndian>(tx_in.txindex)?;
            let scriptcode = key_scriptcode(&self.private_key);
            var_int::write(scriptcode.len() as u64, &mut to_be_hashed)?;
            to_be_hashed.write(&scriptcode)?;
            to_be_hashed.write_u64::<LittleEndian>(tx_in.amount)?;
            to_be_hashed.write_u32::<LittleEndian>(0xffffffff)?;
            to_be_hashed.write(&hash_outputs)?;
            to_be_hashed.write_u32::<LittleEndian>(0)?;
            to_be_hashed.write_u32::<LittleEndian>(0x41)?;
            let hashed = double_sha256(to_be_hashed.get_ref()); // sign will not do sha256

            let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
            let secp = Secp256k1::signing_only();
            let message = Message::from_slice(&hashed).unwrap();
            let mut privk = [0;32];
            privk.copy_from_slice(&self.private_key.from_base58().unwrap()[1..33]);
            let secret_key = SecretKey::from_slice(&privk).expect("32 bytes, within curve order");
            let mut signature = secp.sign(&message, &secret_key);
            signature.normalize_s();
            let mut sig = signature.serialize_der().to_vec();
            sig.push(sighash_type);

            //todo make script_sig with sig
        }

        //construct_input_block
        // for tx_in in inputs.iter() {
        //     writer.write(&tx_in.txid);
        //     writer.write_u32::<LittleEndian>(tx_in.txindex);

        //     // writer.write(script_len);
        // }

        // address
        
        
        // hex::decode(txid).revert + sha256(sha256(writer.write_u32::<LittleEndian>(txindex)?)
        
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
