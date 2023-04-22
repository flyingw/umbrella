use byteorder::{LittleEndian, WriteBytesExt};
use crate::{ctx::Ctx, hash160, network::Network, result::{Error, Result}, serdes::Serializable, var_int};
use crate::op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSH_20, OP_FALSE, OP_RETURN, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use crate::{SIGHASH_ALL, SIGHASH_FORKID};
use secp256k1::{SecretKey, Message, Secp256k1, PublicKey};
use std::io::{Cursor, Read, Write};
use std::io;

#[derive(PartialEq, Debug)]
pub struct Output {
    pub dest: Vec<u8>,
    pub amount: u64,
}

impl Serializable<Output> for Output {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Output> {
        Err(Error::NotImplemented)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        if self.amount > 0 {
            writer.write_u64::<LittleEndian>(self.amount)?;

            let scriptcode = key_scriptcode(&self.dest);
            var_int::write(scriptcode.len() as u64, writer)?;
            writer.write(&scriptcode)?;
        } else {
            let mut xs = Vec::new();
            xs.write_u8(OP_FALSE).unwrap();
            xs.write_u8(OP_RETURN).unwrap();
            xs.write(&get_op_pushdata_code(&self.dest)).unwrap();
            xs.write(&self.dest).unwrap();

            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            writer.write_u8(0x00)?;
            var_int::write(xs.len() as u64, writer)?;
            writer.write(&xs)?;
        }

        Ok(())
    }
}

fn sanitize_tx_data(unspents: &Vec<UnspentBsv>, leftover: &Vec<u8>, message: &Vec<u8>, compressed: bool) -> Vec<Output> {
    let mut res = Vec::new();
    res.push(Output{
        dest: message.clone(),
        amount: 0,
    });
    if unspents.len() == 0 {
        panic!("Transactions must have at least one unspent.");
    }
    if message.len() > 100000 {
        panic!("too long message");
    }
    let total_op_return_size = get_op_return_size(message);
    let calculated_fee = estimate_tx_fee(unspents.len() as u64, compressed, total_op_return_size);
    let total_out = calculated_fee;
    // print!("{}", total_out);
    let total_in: u64 = unspents.iter().map(|x| x.amount).sum();
    let remaining = total_in as i128 - total_out as i128;
    const DUST: i128 = 546;
    if remaining > DUST {
        res.push(Output{
            dest: leftover.to_vec(),
            amount: remaining as u64,
        });
    } else if remaining < 0 {
        panic!("Balance {} is less than {} (including fee).", total_in, total_out);
    }
    res
}

pub struct UnspentBsv {
    pub txid: Vec<u8>,
    pub txindex: u32,
    pub amount: u64,
}

pub struct TxBsv {
    pub unspents: Vec<UnspentBsv>,
    pub outputs: Vec<Output>,
    pub private_key: Vec<u8>,
    pub address: Vec<u8>,
}

impl Serializable<TxBsv> for TxBsv {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<TxBsv> {
        Err(Error::NotImplemented)
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        let output_block = output_block(&self.outputs);
        let hash_outputs = double_sha256(&output_block);

        let inputs = unspents_to_inputs(&self.unspents);

        let hash_prevouts = hash_prevouts(&inputs).unwrap();

        let hash_sequence = hash_sequence(inputs.len()).unwrap();

        let mut tx_in_scripts = Vec::new();
        for tx_in in inputs.iter() {
            let to_be_hashed = to_be_hashed(tx_in, hash_prevouts, hash_sequence, hash_outputs, &self.address).unwrap();
            let hashed = double_sha256(&to_be_hashed); // sign will not do sha256

            let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
            let message = Message::from_slice(&hashed).unwrap();
            let secret_key = private_key_to_secret_key(&self.private_key);
            let mut signature = Secp256k1::signing_only().sign_ecdsa(&message, &secret_key);
            signature.normalize_s();
            let mut sig = signature.serialize_der().to_vec();
            sig.push(sighash_type);

            let mut script_sig = Cursor::new(Vec::new());
            script_sig.write_u8(sig.len() as u8)?;
            script_sig.write(&sig)?;
            let pub_key = secret_key_to_public_key(&secret_key);
            let public_key = pub_key.serialize().to_vec();
            script_sig.write_u8(public_key.len() as u8)?;
            script_sig.write(&public_key)?;

            let mut script_len = Cursor::new(Vec::new());
            var_int::write(script_sig.get_ref().len() as u64, &mut script_len)?;

            tx_in_scripts.push(TxInScriptBsv {
                txid: tx_in.txid.to_vec(),
                txindex: tx_in.txindex,
                amount: tx_in.amount,
                script: script_sig.get_ref().to_vec(),
                script_len: script_len.get_ref().to_vec(),
            });
        }

        writer.write_u32::<LittleEndian>(1)?;
        var_int::write(self.unspents.len() as u64, writer)?;
        for tx_in in tx_in_scripts.iter() {
            tx_in.write(writer, ctx)?;
        }
        var_int::write(self.outputs.len() as u64, writer)?;
        writer.write(&output_block)?;
        writer.write_u32::<LittleEndian>(0)?;
        Ok(())
    }
}

pub struct TxInBsv {
    pub txid: Vec<u8>,
    pub txindex: u32,
    pub amount: u64,
}

pub struct TxInScriptBsv {
    pub txid: Vec<u8>,
    pub txindex: u32,
    pub amount: u64,
    pub script: Vec<u8>,
    pub script_len: Vec<u8>,
}

impl Serializable<TxInScriptBsv> for TxInScriptBsv {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<TxInScriptBsv> {
        Err(Error::NotImplemented)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write(&self.txid)?;
        writer.write_u32::<LittleEndian>(self.txindex)?;
        writer.write(&self.script_len)?;
        writer.write(&self.script)?;
        writer.write_u32::<LittleEndian>(0xffffffff)?;
        Ok(())
    }
}

fn to_be_hashed(tx_in: &TxInBsv, hash_prevouts: [u8; 32], hash_sequence: [u8; 32], hash_outputs: [u8; 32], address: &Vec<u8>) -> Result<Vec<u8>> {
    let mut to_be_hashed = Cursor::new(Vec::new());
    to_be_hashed.write_u32::<LittleEndian>(1)?;
    to_be_hashed.write(&hash_prevouts)?;
    to_be_hashed.write(&hash_sequence)?;
    to_be_hashed.write(&tx_in.txid)?;
    to_be_hashed.write_u32::<LittleEndian>(tx_in.txindex)?;
    let scriptcode = key_scriptcode(&address);
    var_int::write(scriptcode.len() as u64, &mut to_be_hashed)?;
    to_be_hashed.write(&scriptcode)?;
    to_be_hashed.write_u64::<LittleEndian>(tx_in.amount)?;
    to_be_hashed.write_u32::<LittleEndian>(0xffffffff)?;
    to_be_hashed.write(&hash_outputs)?;
    to_be_hashed.write_u32::<LittleEndian>(0)?;
    to_be_hashed.write_u32::<LittleEndian>(0x41)?;
    Ok(to_be_hashed.get_ref().to_vec())
}

fn hash_prevouts(inputs: &Vec<TxInBsv>) -> Result<[u8; 32]> {
    let mut hash_prevouts = Cursor::new(Vec::new());
    for tx_in in inputs.iter() {
        hash_prevouts.write(&tx_in.txid)?;
        hash_prevouts.write_u32::<LittleEndian>(tx_in.txindex)?;
    }
    Ok(double_sha256(&hash_prevouts.get_ref()))
}

fn hash_sequence(n: usize) -> Result<[u8; 32]> {
    let mut hash_sequence1 = Cursor::new(Vec::new());
    for _ in 1..=n {
        hash_sequence1.write_u32::<LittleEndian>(0xffffffff)?;
    }
    Ok(double_sha256(&hash_sequence1.get_ref()))
}

fn unspents_to_inputs(unspents: &Vec<UnspentBsv>) -> Vec<TxInBsv> {
    let mut inputs = Vec::new();
    for unspent in unspents.iter() {
        let mut txid = hex::decode(&unspent.txid).unwrap();
        txid.reverse();
        inputs.push(TxInBsv{
            txid: txid,
            txindex: unspent.txindex,
            amount: unspent.amount,
        });
    }
    inputs
}

fn output_block(outputs: &Vec<Output>) -> Vec<u8> {
    let mut output_block = Cursor::new(Vec::new());
    for tx_out in outputs.iter() {
        tx_out.write(&mut output_block, &mut ()).unwrap();
    }
    output_block.get_ref().to_vec()
}

fn private_key_to_secret_key(private_key: &Vec<u8>) -> SecretKey {
    let mut privk = [0;32];
    privk.copy_from_slice(&bs58::decode(&private_key).into_vec().unwrap()[1..33]);
    SecretKey::from_slice(&privk).expect("32 bytes, within curve order")
}

fn secret_key_to_public_key(secret_key: &SecretKey) -> PublicKey {
    let secp = Secp256k1::signing_only();
    PublicKey::from_secret_key(&secp, &secret_key)
}


fn key_scriptcode(dest: &Vec<u8>) -> Vec<u8> {
    let mut xs = Vec::new();
    xs.write_u8(OP_DUP).unwrap();
    xs.write_u8(OP_HASH160).unwrap();
    xs.write_u8(OP_PUSH_20).unwrap();
    xs.write(&address_to_public_key_hash(&dest)).unwrap();
    xs.write_u8(OP_EQUALVERIFY).unwrap();
    xs.write_u8(OP_CHECKSIG).unwrap();
    xs
}

fn get_op_pushdata_code(dest: &Vec<u8>) -> Vec<u8> {
    let mut xs = Vec::new();
    let length_data = dest.len();
    if length_data <= 0x4c {
        xs.write_u8(length_data as u8).unwrap();
    } else if length_data <= 0xff {
        xs.write_u8(OP_PUSHDATA1).unwrap();
        xs.write_u8(length_data as u8).unwrap();
    } else if length_data <= 0xffff {
        xs.write_u8(OP_PUSHDATA2).unwrap();
        xs.write_u16::<LittleEndian>(length_data as u16).unwrap();
    } else {
        xs.write_u8(OP_PUSHDATA4).unwrap();
        xs.write_u32::<LittleEndian>(length_data as u32).unwrap();
    }
    xs
}

fn int_to_varint(val: u64) -> Vec<u8> {
    let mut xs = Vec::new();
    var_int::write(val as u64, &mut xs).unwrap();
    xs
}

fn get_op_return_size(message: &Vec<u8>) -> u64 {
    let mut op_return_size = 
        8 // int64_t amount 0x00000000
        + [OP_FALSE, OP_RETURN].len() // 2 bytes
        + get_op_pushdata_code(message).len() // 1 byte if <75 bytes, 2 bytes if OP_PUSHDATA1...
        + message.len(); // Max 220 bytes at present
    // "Var_Int" that preceeds OP_RETURN - 0xdf is max value with current 220 byte limit (so only adds 1 byte)
    op_return_size += int_to_varint(op_return_size as u64).len();
    op_return_size as u64
}

fn get_fee(speed: &str) -> f64 {
    match speed {
        "fast"   => 2.0,
        "medium" => 1.0,
        "slow"   => 0.5,
        _ => panic!("Invalid speed argument.")
    }
}

fn estimate_tx_fee(n_in: u64, compressed: bool, op_return_size: u64) -> u64 {
    let n_out = 1;
    let satoshis = get_fee(&"slow");
    let estimated_size =
        4 + // version
        n_in * (if compressed { 148 } else { 180 })
        + (int_to_varint(n_in).len() as u64)
        + n_out * 34  // excluding op_return outputs, dealt with separately
        + (int_to_varint(n_out).len() as u64)
        + op_return_size  // grand total size of op_return outputs(s) and related field(s)
        + 4;  // time lock
    f64::ceil((estimated_size as f64) * satoshis) as u64
}

fn b58decode(string: &Vec<u8>) -> Vec<u8> {
    bs58::decode(string).into_vec().unwrap()
}

fn b58decode_check(string: &Vec<u8>) -> Vec<u8> {
    let decoded = &b58decode(string)[..];
    let mut shortened = vec![0; decoded.len()-4];
    shortened.copy_from_slice(&decoded[ .. decoded.len()-4]);
    let decoded_checksum: [u8;4] = decoded[decoded.len() - 4 .. ].try_into().unwrap();
    let hash_checksum = double_sha256_checksum(&shortened);
    if decoded_checksum != hash_checksum {
        panic!("Decoded checksum {:?} derived from \"{:?}\" is not equal to hash checksum {:?}.", decoded_checksum, string, hash_checksum)
    }
    shortened
}

fn sha256(bytestr: &[u8]) -> [u8;32] {
    use ring::digest::{digest, SHA256};
    digest(&SHA256, bytestr).as_ref().try_into().unwrap()
}

fn double_sha256(bytestr: &Vec<u8>) -> [u8;32] {
    sha256(&sha256(&bytestr[..]))
}

fn double_sha256_checksum(bytestr: &Vec<u8>) -> [u8;4] {
    double_sha256(bytestr)[..4].try_into().unwrap()
}

fn private_key_to_secret_key_str(wif: &String) -> SecretKey {
    let mut privk = [0;32];
    privk.copy_from_slice(&bs58::decode(&wif).into_vec().unwrap()[1..33]); 
    SecretKey::from_slice(&privk).expect("32 bytes, within curve order")
}

fn private_key_to_public_key(wif: &String) -> Vec<u8> {
    let secret_key = private_key_to_secret_key_str(wif);
    let secp = Secp256k1::new();
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
    pub_key.serialize().to_vec()
}

fn b58encode_check(bytestr: Vec<u8>) -> Vec<u8> {
    let mut xs = vec![];
    xs.extend(bytestr.clone());
    xs.extend(double_sha256_checksum(&bytestr).to_vec());
    bs58::encode(xs).into_vec()
}

fn public_key_to_address(_public_key: Vec<u8>, _network: &Network) -> Vec<u8> {
    let mut xs = hash160(&_public_key[..]).0.to_vec();
    xs.insert(0, _network.legacyaddr_pubkeyhash_flag());
    b58encode_check(xs)
}

fn address_to_public_key_hash(address: &Vec<u8>) -> Vec<u8> {
    b58decode_check(address)[1..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_prevouts() {
        let inputs = unspents_to_inputs(&vec![UnspentBsv{
            txid: "cec6ac057861ee3ad37fa39503b39057ada889578a2117bd775264d1a5289cfd".as_bytes().to_vec(),
            txindex: 0,
            amount: 5000000000,
        }]);
        let res = hash_prevouts(&inputs).unwrap();
        assert_eq!(hex::encode(res), "c5013f5caba34be88c9c7c9e089168d115580cd1a998ccd50517ae134af04e5c")
    }

    #[test]
    fn test_to_be_hashed() {
        let inputs = unspents_to_inputs(&vec![UnspentBsv{
            txid: "cec6ac057861ee3ad37fa39503b39057ada889578a2117bd775264d1a5289cfd".as_bytes().to_vec(),
            txindex: 0,
            amount: 5000000000,
        }]);
        let outputs = vec![Output{
                dest: "hi".as_bytes().to_vec(),
                amount: 0,
            }, Output{
                dest: "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj".as_bytes().to_vec(),
                amount: 4999999897,
            }
        ];
        let address = "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj".as_bytes().to_vec();
        
        let output_block = output_block(&outputs);
        assert_eq!(hex::encode(&output_block), "000000000000000005006a02686999f1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac");
        let hash_outputs = double_sha256(&output_block);
        let hash_prevouts = hash_prevouts(&inputs).unwrap();
        let hash_sequence = hash_sequence(inputs.len()).unwrap();
        for tx_in in inputs.iter() {
            let to_be_hashed = to_be_hashed(tx_in, hash_prevouts, hash_sequence, hash_outputs, &address).unwrap();
            assert_eq!(hex::encode(to_be_hashed), "01000000c5013f5caba34be88c9c7c9e089168d115580cd1a998ccd50517ae134af04e5c3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044fd9c28a5d1645277bd17218a5789a8ad5790b30395a37fd33aee617805acc6ce000000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00f2052a01000000ffffffff141cae1e7372d1e8e96d219392131e28992dc83690e62ef74152dd0393dc8d100000000041000000")
        }
    }

    #[test]
    fn test_utils() {
        let decoded = b58decode(&"2yGEbwRFyft7uRe2t".as_bytes().to_vec());
        assert_eq!(decoded, "hello there!".to_string().as_bytes());
        assert_eq!(&decoded[ .. decoded.len() - 4], "hello th".to_string().as_bytes());
        assert_eq!(&decoded[decoded.len() - 4 .. ], "ere!".to_string().as_bytes());

        let private_key = "cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh".to_string();
        let network = Network::BsvRegtest;
        let public_key = private_key_to_public_key(&private_key);
        let address = public_key_to_address(public_key, &network);
        assert_eq!(address, "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj".to_string().as_bytes());
    }

    #[test]
    fn test_output_write1() {
        let mut is2 = Cursor::new(Vec::new());
        Output{
            dest: "hi".as_bytes().to_vec(),
            amount: 0,
        }.write(&mut is2, &mut ()).unwrap();
        let res2 = hex::encode(&is2.get_ref());
        let exp2 = "000000000000000005006a026869";
        assert_eq!(res2, exp2);
    }

    #[test]
    fn test_output_write2() {
        let mut is2 = Cursor::new(Vec::new());
        Output{
            dest: "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj".as_bytes().to_vec(),
            amount: 4999999897,
        }.write(&mut is2, &mut ()).unwrap();
        let res2 = hex::encode(&is2.get_ref());
        let exp2 = "99f1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac";
        assert_eq!(res2, exp2);
    }

    #[test]
    fn test_signature_bsv() {
        use secp256k1::{Message, Secp256k1};
        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
        assert_eq!(sighash_type, 0x41);

        let private_key = "cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh".to_string();

        // let hashed = "1de06a2fabae2b020ea38298111cd22b84c7dd7fc7473eb07da6a51df8ee85a6";
        let hashed = "0ee40f326fb83415461348dd0a6ebe5081314dfa30845e6948dc9d043fcb8c7a"; // double sha256
        let signature_expected = "304502210090298a2bf23e5640396400e4afea95c872b7da1a90abba35da7aab3d1299627702206196a592a5a2d99f5dfba4830965e97ca5ae7359a1e72ae2f712dde60a80db9b41";

        let secp = Secp256k1::signing_only();
        let message = Message::from_slice(&hex::decode(hashed).unwrap()).unwrap();
        let secret_key = private_key_to_secret_key_str(&private_key);
        assert_eq!(secret_key, SecretKey::from_slice(&hex::decode("748c9dc4643c0ee4d0dd047277af81bf8cee1b4947ed6fd84cb7b660a5e1f613").unwrap()).unwrap());
        let mut signature = secp.sign_ecdsa(&message, &secret_key);
        signature.normalize_s();
        let mut sig = signature.serialize_der().to_vec();
        sig.push(sighash_type);
        
        assert_eq!(hex::encode(sig), signature_expected)
    }

    #[test]
    fn test_write() {
        // input data
        let private_key = "cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh".to_string();
        let unspents = vec![UnspentBsv{
            amount: 5000000000,
            txid: "cec6ac057861ee3ad37fa39503b39057ada889578a2117bd775264d1a5289cfd".as_bytes().to_vec(),
            txindex: 0
        }];
        let msg = "hi".as_bytes().to_vec();
        let network = Network::BsvRegtest;

        // derived data from input
        let public_key = private_key_to_public_key(&private_key);
        let pk_compressed = public_key.len() == 33;
        assert_eq!(pk_compressed, true);
        let address = public_key_to_address(public_key, &network);

        // test sanitize_tx_data
        let outputs = sanitize_tx_data(&unspents, &address, &msg, pk_compressed);
        assert_eq!(outputs, vec![Output{
            dest: "hi".as_bytes().to_vec(),
            amount: 0,
        }, Output{
            dest: "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj".as_bytes().to_vec(),
            amount: 4999999897,
        }]);

        let mut is = Cursor::new(Vec::new());
        TxBsv {
            unspents,
            outputs,
            private_key: private_key.as_bytes().to_vec(),
            address: address.to_vec(),
        }.write(&mut is, &mut ()).unwrap();
        let res = hex::encode(&is.get_ref());
        let exp = "0100000001fd9c28a5d1645277bd17218a5789a8ad5790b30395a37fd33aee617805acc6ce000000006b48304502210090298a2bf23e5640396400e4afea95c872b7da1a90abba35da7aab3d1299627702206196a592a5a2d99f5dfba4830965e97ca5ae7359a1e72ae2f712dde60a80db9b41210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000005006a02686999f1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000";
        assert_eq!(res, exp)
    }
}
