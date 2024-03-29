#[macro_use]
extern crate log;

pub mod address;
pub mod messages;
pub mod network;
pub mod script;
pub mod transaction;
pub mod util;
pub mod sighash;
pub mod hash128;
pub mod hash256;
pub mod hash512;
pub mod amount;
pub mod bits;
pub mod hash160;
pub mod result;
pub mod serdes;
pub mod conf;
pub mod cashaddr;
pub mod var_int;
pub mod op_codes;
pub mod stack;
pub mod interpreter;
pub mod keys;
pub mod ctx;
pub mod lil_rlp;
pub mod ecies;
pub mod json;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes_ctr::{Aes256Ctr, stream_cipher::NewStreamCipher};
use amount::{Amount, Units};
use cashaddr::cashaddr_decode;
use conf::Opt;
use ctx::{Ctx, EncCtx};
use hash160::hash160;
use hash256::Hash256;
use hash512::Hash512;
use keys::{slice_to_public, Address};
use messages::bsv::{private_key_to_public_key, public_key_to_address, address_to_public_key_hash, estimate_tx_fee, get_op_return_size};
use messages::{Tx, Tx2, TxIn, OutPoint, TxOut, Hello, Message, MsgHeader, commands};
use network::{Network, PEERS_BSV_MAINNET};
use op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_FALSE, OP_RETURN};
use rand::seq::{SliceRandom, IteratorRandom};
use result::{Error, Result};
use script::Script;
use secp256k1::{ecdh, Secp256k1, SecretKey, PublicKey};
use sighash::{bip143_sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
use std::io;
use std::io::{ErrorKind};
use std::net::{Shutdown, TcpStream, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use structopt::StructOpt;
use tiny_keccak::Keccak;
use transaction::generate_signature;

const NULL_IV: [u8; 16] = [0;16];

// Creates public key hash script.
fn pk_script(addr: &str, network: Network) -> Script {
    let hash = cashaddr_decode(addr, network).expect("correct cash address");
    let mut payload = [1;20];
    payload.copy_from_slice(&hash.0[..20]);
    pk_script_gen(&payload.to_vec())
}

fn pk_script_gen(data: &Vec<u8>) -> Script {
    let mut s = Script::new();
    s.append(OP_DUP);
    s.append(OP_HASH160);
    s.append_data(&data);
    s.append(OP_EQUALVERIFY);
    s.append(OP_CHECKSIG);
    s
}

fn pk_script_data(dest: &Vec<u8>) -> Script {
    let mut s = Script::new();
    s.append(OP_FALSE);
    s.append(OP_RETURN);
    s.append_data(&dest);
    s
}

/// Creates a sigscript to sign a p2pkh transaction
fn sig_script(sig: &[u8], public_key: &[u8; 33]) -> Script {
    let mut sig_script = Script::new();
    sig_script.append_data(sig);
    sig_script.append_data(public_key);
    sig_script
}

pub fn create_transaction(opt: &Opt) -> Tx {
    let network = opt.network.network();
    let pub_script = pk_script(&opt.sender().in_address(), network);
    let chng_pk_script = pk_script(&opt.sender().out_address(), network);
    let dump_pk_script = pk_script(&opt.data().dust_address, network);
    let in_amount = Amount::from(opt.sender().in_amount(), Units::Bch);
    let outputs = vec![
        TxOut{ amount: Amount::from(opt.sender().change(), Units::Bch), pk_script: chng_pk_script,}, 
        TxOut{ amount: Amount::from(opt.data().dust_amount, Units::Bch), pk_script: dump_pk_script, },
    ];
    create_tx(&opt, in_amount, 2, 0x00000000, outputs, &pub_script)
}

pub fn create_transaction_bsv(opt: &Opt) -> Tx {
    let network = &opt.network.network();
    
    let private_key = opt.sender().secret().unwrap();
    let public_key = private_key_to_public_key(&private_key);
    let address = public_key_to_address(public_key, network);

    let pub_script = pk_script_gen(&address_to_public_key_hash(&address));
    let data = &opt.data().data.0;
    if data.len() > 100_000 {
        panic!("too long message");
    }
    let data_script = pk_script_data(&data);

    let mut outputs = Vec::new();
    outputs.push(TxOut{ amount: Amount::from(0.0, Units::Bch), pk_script: data_script });

    let in_amount = Amount::from(opt.sender().in_amount(), Units::Bch);
    let amount = in_amount.to(Units::Sats) as u64;
    let calculated_fee = estimate_tx_fee(1, true, get_op_return_size(&data));
    let remaining = amount as i128 - calculated_fee as i128;
    if remaining > 546 as i128 {
        outputs.push(TxOut{ amount: Amount(remaining as u64), pk_script: pub_script.clone() });
    } else if remaining < 0 {
        panic!("Balance {} is less than {} (including fee).", amount, calculated_fee);
    }

    create_tx(&opt, in_amount, 1, 0xffffffff, outputs, &pub_script)
}

fn create_tx(opt: &Opt, in_amount: Amount, version: u32, sequence: u32, outputs: Vec<TxOut>, pub_script: &Script) -> Tx {
    let mut tx = Tx {
        version: version,
        inputs: vec![TxIn{
            prev_output: OutPoint {
                hash:  opt.sender().outpoint_hash(),
                index: opt.sender().outpoint_index(),
            },
            sequence: sequence,
            ..Default::default()
        }],
        outputs: outputs,
        lock_time: 0,
    };
    tx.inputs[0].sig_script = create_sig_script(&opt, in_amount, &mut tx, &pub_script);
    tx
}

fn create_sig_script(opt: &Opt, in_amount: Amount, tx: &mut Tx, pub_script: &Script) -> Script {
    let secp = Secp256k1::new();
    let mut cache = SigHashCache::new();
    
    let mut privk = [0;32];
    privk.copy_from_slice(&bs58::decode(&opt.sender().secret().unwrap()).into_vec().unwrap()[1..33]); 

    let secret_key = SecretKey::from_slice(&privk).expect("32 bytes, within curve order");
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = bip143_sighash(tx, 0, &pub_script.0, in_amount, sighash_type, &mut cache).unwrap();
    let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    sig_script(&signature, &pub_key.serialize())
}

fn create_transaction2(opt: &Opt) -> Tx2 {
    let mut address: Address = Default::default();
    let decoded_address = hex::decode(&opt.sender().out_address()).unwrap();
    address.copy_from_slice(&decoded_address);

    Tx2 {
        nonce: 2u128,
        gas_price: opt.sender().gas_price(),
        gas: opt.sender().gas(),
        call: address,
        value: opt.sender().value(),
        data: opt.data().data.0.clone(),
        r: Hash256::default(),
        s: Hash256::default(),
        v: 0u64,
    }
}

pub fn ctx(secret: &SecretKey
    , auth_data: &[u8]
    , ecdhe_secret_key: SecretKey
    , nonce: Hash256
    , auth_cipher: Vec<u8>
    , public_key: PublicKey) -> Result<impl Ctx> {

    ecies::decrypt(secret, &[], auth_data).map(|ack| {
        let mut remote_nonce: Hash256 = Hash256::default();

        let remote_ephemeral = slice_to_public(&ack[0..64]).unwrap();
        remote_nonce.copy_from_slice(&ack[64..(64+32)]);        

        let shared = &ecdh::shared_secret_point(&remote_ephemeral, &ecdhe_secret_key)[..32];
        
        let mut nonce_material = Hash512::default();
        (&mut nonce_material[0..32]).copy_from_slice(remote_nonce.as_bytes());
        (&mut nonce_material[32..64]).copy_from_slice(nonce.as_bytes());
        let mut key_material = Hash512::default();
        (&mut key_material[0..32]).copy_from_slice(&shared);
        Keccak::keccak256(nonce_material.as_bytes_mut(), &mut key_material[32..64]);
        
        let mut key_material_keccak = Hash256::default();
        Keccak::keccak256(key_material.as_bytes(), key_material_keccak.as_bytes_mut());

        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
        
        let mut key_material_keccak = Hash256::default();
        Keccak::keccak256(key_material.as_bytes(), key_material_keccak.as_bytes_mut());

        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());

        // Using a 0 IV with CTR is fine as long as the same IV is never reused with the same key.
        // This is the case here: ecdh creates a new secret which will be the symmetric key used
        // only for this session the 0 IV is only use once with this secret, so we are in the case
        // of same IV use for different key.
        let encoder = Aes256Ctr::new(GenericArray::from_slice(&key_material[32..64]), GenericArray::from_slice(&NULL_IV));
        let decoder = Aes256Ctr::new(GenericArray::from_slice(&key_material[32..64]), GenericArray::from_slice(&NULL_IV));

        let mut key_material_keccak = Hash256::default();
        Keccak::keccak256(key_material.as_bytes(), key_material_keccak.as_bytes_mut());

        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());

        let mac_encoder_key: SecretKey = SecretKey::from_slice(&key_material[32..64]).unwrap();

        let mut egress_mac = Keccak::new_keccak256();
        let mut mac_material = Hash256::from_slice(&key_material[32..64]) ^ remote_nonce;
        egress_mac.update(mac_material.as_bytes());
        egress_mac.update(&auth_cipher);

        // message auth code for sent messages here
        // last part is something we've received as auth acknowledgement unencrypted
        let mut ingress_mac = Keccak::new_keccak256();
        mac_material = Hash256::from_slice(&key_material[32..64]) ^ nonce;
        ingress_mac.update(mac_material.as_bytes());
        ingress_mac.update(&auth_data.clone().to_vec());
        
        EncCtx {
            encoder: encoder,
            decoder: decoder,
            mac_encoder_key: mac_encoder_key,
            egress_mac: egress_mac,
            ingress_mac: ingress_mac,
            public_key: public_key,
            expected: commands::HELLO,
        }
    }).map_err(|_e| {
        Error::Unsupported(String::from("need special error"))
    })
}

///
/// Send transaction to selected network.
/// 
pub fn main() {
    let opt = Opt::from_args();
    
    stderrlog::new().module(module_path!())
        .quiet(opt.quiet)
        .verbosity(4)
        .modules(vec!("umbrella", "bch"))
        .init().unwrap();

    trace!("Options {:?}", opt);

    let network = opt.network.network();

    let mut rng = rand::thread_rng();
    
    let mut stream = {
        let mut i = 0;
        loop {
            let seed = 
                if network == Network::BsvMainnet {
                    SocketAddr::from(PEERS_BSV_MAINNET[i])
                } else {
                    let seed = network.seeds();
                    let seed = seed.choose(&mut rng).unwrap();
                    let seed = [&seed, ":", &network.port().to_string()].concat();
                    seed.to_socket_addrs().unwrap().choose(&mut rng).unwrap()
                };
            trace!("{} Connecting to {}", i + 1, &seed);
            match TcpStream::connect_timeout(&seed, Duration::from_secs(1)) {
                Ok(stream) => break stream,
                Err(error) => match error.kind() {
                    ErrorKind::TimedOut => i += 1,
                    ErrorKind::ConnectionRefused => i += 1,
                    _ => panic!("{}", error),
                }
            }
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    
    let magic = network.magic();
    let mut partial: Option<Box<dyn MsgHeader>> = None;
    let mut is = stream.try_clone().unwrap();

    let enc_opt = opt.sender().encryption_conf();
    let our_version = opt.sender().version(&enc_opt);    
    debug!("Write {:#?}", our_version);
    
    our_version.write(&mut stream, magic, &mut ()).unwrap();

    let lis = thread::spawn(move || {
        let mut ct: Box<dyn Ctx> = Box::new(());
        debug!("Connected.");
        loop {
            let message = match (&partial, &enc_opt) {
                (Some(header),_) => Message::read_partial(&mut is, header.as_ref(), &mut *ct),
                (None, Some(_x)) => Message::read2(&mut is, magic[..3].try_into().expect("shortened magic"), &mut *ct),
                (None,None)      => Message::read(&mut is, network.magic(), &mut *ct),
            };

            match message {
                Ok(message) => {
                    if let Message::Partial( header) = message {
                        partial = Some(header);
                    } else {
                        partial = None;
                        match message {
                            Message::Authack(mut data) => {
                                debug!("Auth ack {:?}", hex::encode(&data));
                                let enc_opt = &enc_opt.as_ref().unwrap();

                                ct = Box::new(ctx(&enc_opt.node_secret
                                    , &mut data
                                    , enc_opt.msg_secret
                                    , enc_opt.nonce
                                    , enc_opt.enc_version.clone()
                                    , enc_opt.node_public).unwrap());

                                let hello = Hello {
                                    public_key: enc_opt.node_public,
                                };
                                Message::Hello(hello).write(&mut is, magic, &mut *ct).unwrap();
                                ct.expect(commands::HELLO);
                            }
                            Message::Hello(h) => {
                                debug!("Hello {:?}", h);
                                ct.expect(commands::STATUS)
                            }
                            Message::Status(status) => {
                                debug!("Status {:?}", status);
                                let secret: SecretKey = match opt.sender().crypto() {
                                    Some(ref s) => json::read_secret(s, &opt.sender().password()),
                                    None => SecretKey::from_str(&opt.sender().secret().unwrap()).unwrap(),
                                };
                                
                                Message::Status(status.clone()).write(&mut is, magic, &mut *ct).unwrap();
                                let mut tx = create_transaction2(&opt);
                                tx = tx.sign(&secret, Some(status.network_id as u64));
                                let mx = Message::Tx2(tx);
                                mx.write(&mut is, magic, &mut *ct).unwrap();

                                return Ok(mx);
                            }
                            Message::Version(v) => {
                                debug!("Version {:?}, verract", v);
                                if network == Network::BsvMainnet {
                                    if !v.user_agent.starts_with("/Bitcoin SV") {
                                        warn!("bad user agent {}", v.user_agent);
                                    }
                                }
                            }
                            Message::Verack => {
                                debug!("Write {:#?}", Message::Verack);
                                Message::Verack.write(&mut is, magic, &mut ()).unwrap();
                            }
                            Message::Ping(ref ping) => {
                                debug!("Write {:#?}", ping);
                                Message::Pong(ping.clone()).write(&mut is, magic, &mut ()).unwrap();
                            }
                            Message::FeeFilter(ref fee) => {
                                debug!("Min fee {:?}, validate", fee.minfee);
                                let tx =
                                    if network == Network::BsvRegtest || network == Network::BsvMainnet {
                                        create_transaction_bsv(&opt)
                                    } else {
                                        create_transaction(&opt)
                                    };
                                let mx = Message::Tx(tx);
                                mx.write(&mut is, magic, &mut ()).unwrap();
                                return Ok(mx);
                            }
                            Message::Reject(ref reject) => {
                                debug!("rejected {:?}", reject);
                                return Ok(Message::Reject(reject.clone()));
                            }
                            _ => trace!("not handled {:?}",  message),
                        }
                    }
                }
                Err(e) => {
                    if let Error::IOError(ref e) = e {
                        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
    });

    match lis.join().expect("couldn't join thread") {
        Ok(Message::Tx(mut v))  => debug!("transaction hash: {:?}", v.hash()),
        Ok(Message::Tx2(mut v)) => debug!("transaction hash: {:?}", v.hash()),
        Ok(m)   => debug!("{:?}", m),
        Err(r)  => debug!("{:?}", r),
    };

    stream.shutdown(Shutdown::Both).unwrap();
}

#[cfg(test)]
mod tests {
    use conf::{Network, Wallet, Data, HexData};
    use serdes::Serializable;
    use std::io::Cursor;
    use super::*;

    #[test]
    fn test_bch() {
        let tx = create_transaction(&Opt{
            network: Network::BCHReg{
                sender: Wallet{
                    in_address: "bchreg:qphrcrv0ua00njxu6jd7rs7n7ntepmvvuvglc80jdn".to_string(),
                    in_amount: f64::from_str("1.0000").unwrap(),
                    outpoint_hash: Hash256::decode("df2741a4164630be86a7528f05da3cdc4acc514569a89017eea4b303a0d66412").unwrap(),
                    outpoint_index: 0,
                    secret: "cN4hMbVEjSwQEafm5Morxh59CeTpK6MdE4oaVf52TXMYr6CkQQ4F".to_string(),
                    out_address: "bchreg:qqkwrtcw4hqnnsdpsntey63ll8qlr2phsczpqydl98".to_string(),
                    change: f64::from_str("0.9998").unwrap(),
                },
                data: Data{
                    dust_address: "bchreg:qq6j8yswty4n4unqqcxp2ujuy6eh5769h52dt69vml".to_string(),
                    dust_amount: f64::from_str("0.0001").unwrap(),
                    data: HexData::from_str("68686c6c6f2c7361696c6f72").unwrap(),
                },
            },
            quiet: false,
        });
        let mut is = Cursor::new(Vec::new());
        tx.write(&mut is, &mut ()).unwrap();
        let res = hex::encode(&is.get_ref());
        let exp = "02000000011264d6a003b3a4ee1790a8694551cc4adc3cda058f52a786be304616a44127df000000006b483045022100d8e386aab795d56f9d7b7d6a51e5e79f9838227bc87b264140399fa31846cb8802203c3726092a64e6c9979e38a422a56292d76dfd0ac7fdb8201386101af5b277594121029239a0bf858ee84dc7dc17cd036967038091ca44eccad3d430e60be6c7cec6100000000002e092f505000000001976a9142ce1af0eadc139c1a184d7926a3ff9c1f1a8378688ac10270000000000001976a9143523920e592b3af260060c15725c26b37a7b45bd88ac00000000";
        assert_eq!(res, exp)
    }

    #[test]
    fn test_bsv() {
        let tx = create_transaction_bsv(&Opt{
            network: Network::BSVReg{
                sender: Wallet{
                    in_address: "".to_string(), // unused
                    in_amount: f64::from_str("50.00000000").unwrap(),
                    outpoint_hash: Hash256::decode("cec6ac057861ee3ad37fa39503b39057ada889578a2117bd775264d1a5289cfd").unwrap(),
                    outpoint_index: 0,
                    secret: "cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh".to_string(),
                    out_address: "".to_string(), // unused
                    change: 0.0, // unused
                },
                data: Data{
                    dust_address: "".to_string(), // unused
                    dust_amount: 0.0, // unused
                    data: HexData::from_str("6869").unwrap(),
                },
            },
            quiet: false,
        });
        let mut is = Cursor::new(Vec::new());
        tx.write(&mut is, &mut ()).unwrap();
        let res = hex::encode(&is.get_ref());
        let exp = "0100000001fd9c28a5d1645277bd17218a5789a8ad5790b30395a37fd33aee617805acc6ce000000006b48304502210090298a2bf23e5640396400e4afea95c872b7da1a90abba35da7aab3d1299627702206196a592a5a2d99f5dfba4830965e97ca5ae7359a1e72ae2f712dde60a80db9b41210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000005006a02686999f1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000";
        assert_eq!(res, exp)
    }
}
