#[macro_use]
extern crate log;

extern crate rust_scrypt;
extern crate serde_json;

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

pub use serdes::Serializable;
pub use result::{Error, Result};
pub use amount::{Amount, Units};
pub use hash160::{Hash160, hash160};
pub use hash256::{sha256d, Hash256};
use conf::Opt;
use structopt::StructOpt;

use network::Network;
use messages::{Tx, Tx2, TxBsv, TxIn, OutPoint, TxOut, Hello};
use messages::{Message,MsgHeader};
use std::time::Duration;
use script::Script;
use secp256k1::{ecdh, Secp256k1, SecretKey, PublicKey};
use sighash::{bip143_sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
use transaction::generate_signature;
use rust_base58::base58::FromBase58;
use aes_ctr::Aes256Ctr;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes_ctr::stream_cipher::NewStreamCipher;

use std::str::FromStr;
use std::thread;
use crate::messages::commands;
use ctx::{Ctx,EncCtx};
use tiny_keccak::Keccak;
use crate::keys::{slice_to_public, Address};

const NULL_IV: [u8; 16] = [0;16];

// Creates public key hash script.
fn pk_script(addr: &str) -> Script {
    let mut s = Script::new();
    let mut payload = [1;20];

    use cashaddr::cashaddr_decode;

    let hash = cashaddr_decode(addr, Network::Regtest).expect("correct cash address");
    payload.copy_from_slice(&hash.0[..20]);

    use op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};

    s.append(OP_DUP);
    s.append(OP_HASH160);
    s.append_data(&payload);
    s.append(OP_EQUALVERIFY);
    s.append(OP_CHECKSIG);
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
    let pub_script      = pk_script(&opt.sender().in_address());
    let chng_pk_script  = pk_script(&opt.sender().out_address());
    let dump_pk_script  = pk_script(&opt.data().dust_address);

    trace!("pk: {:?}", &pub_script);
    trace!("ck: {:?}", &chng_pk_script);
    trace!("dk: {:?}", &dump_pk_script);

    let mut tx = Tx {
        version: 2,
        inputs: vec![TxIn{
            prev_output: OutPoint {
                hash:  opt.sender().outpoint_hash(),
                index: opt.sender().outpoint_index(),
            },
            ..Default::default()
        }],
        outputs: vec![
            TxOut{ amount: Amount::from(opt.sender().change(), Units::Bch), pk_script: chng_pk_script,}, 
            TxOut{ amount: Amount::from(opt.data().dust_amount, Units::Bch), pk_script: dump_pk_script, }],
        lock_time:0
    };

    let secp = Secp256k1::new();
    let mut cache = SigHashCache::new();
    
    let mut privk = [0;32];
    privk.copy_from_slice(&opt.sender().secret().unwrap().from_base58().unwrap()[1..33]); 

    let secret_key = SecretKey::from_slice(&privk).expect("32 bytes, within curve order");
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = bip143_sighash(&mut tx, 0, &pub_script.0, Amount::from(opt.sender().in_amount(), Units::Bch), sighash_type, &mut cache).unwrap();
    let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    let sig_script = sig_script(&signature, &pub_key.serialize());

    tx.inputs[0].sig_script = sig_script;

    return tx;
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
        data: opt.data().data.as_vec(),
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
        use crate::hash512::Hash512;

        let mut remote_nonce: Hash256 = Hash256::default();

        let remote_ephemeral = slice_to_public(&ack[0..64]).unwrap();
        remote_nonce.copy_from_slice(&ack[64..(64+32)]);		

        let shared = ecdh::SharedSecret::new_with_hash(&remote_ephemeral, &ecdhe_secret_key, &mut hash);
        
		let mut nonce_material = Hash512::default();
		(&mut nonce_material[0..32]).copy_from_slice(remote_nonce.as_bytes());
		(&mut nonce_material[32..64]).copy_from_slice(nonce.as_bytes());
		let mut key_material = Hash512::default();
        (&mut key_material[0..32]).copy_from_slice(&shared[..]);
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

    use rand::seq::{SliceRandom, IteratorRandom};

    let mut rng = rand::thread_rng();
    let seed = network.seeds();
    let seed = seed.choose(&mut rng).unwrap();
    let seed = [&seed, ":", &network.port().to_string()].concat();

    use std::net::{SocketAddr, ToSocketAddrs};
    let seed: SocketAddr = seed.to_socket_addrs().unwrap().choose(&mut rng).unwrap();

    use std::net::TcpStream;
    
    let mut stream = TcpStream::connect_timeout(&seed, Duration::from_secs(1)).unwrap();
    // + kind: ConnectionRefused for next seed
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    
    let magic = network.magic();
    let mut partial: Option<Box<dyn MsgHeader>> = None;
    let mut is = stream.try_clone().unwrap();

    let enc_opt = opt.sender().encryption_conf();
    let our_version = opt.sender().version(&enc_opt);    
    debug!("Write {:#?}", our_version);
    
    our_version.write(&mut stream, magic, &mut ()).unwrap();

    use std::io;
    use std::convert::TryInto;

    let lis = thread::spawn(move || {
        let mut ct: Box<dyn Ctx> = Box::new(());
        debug!("Connected {:?}", &seed);
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
                            }
                            Message::Verack => {
                                debug!("Write {:#?}", Message::Verack);
                                Message::Verack.write(&mut is, magic, &mut ()).unwrap();
                            }
                            Message::Ping(ref ping) => {
                                debug!("Write {:#?}", ping);
                                Message::Pong(ping.clone()).write(&mut is, magic, &mut ()).unwrap();
                            }
                            Message::FeeFilter(ref fee) if network == Network::BsvRegtest => {
                                debug!("Min fee {:?}, validate", fee.minfee);
                                // let mx = Message::TxBsv(opt);
                                // mx.write(&mut is, magic, &mut ()).unwrap();
                                // return Ok(mx);
                            }
                            Message::FeeFilter(ref fee) => {
                                let tx = create_transaction(&opt);
                                debug!("Min fee {:?}, validate", fee.minfee);
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
                        if e.kind() == io::ErrorKind::WouldBlock || 
                            e.kind() == io::ErrorKind::TimedOut {
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

    use std::net::Shutdown;
    stream.shutdown(Shutdown::Both).unwrap();
}

fn hash(output: &mut [u8], x: &[u8], _y: &[u8]) -> i32 {
    output.copy_from_slice(x);
    1
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::*;
    #[test]
    fn test_write() {
        let mut is = Cursor::new(Vec::new());
        let tx = TxBsv {
            key: (&"cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh").to_string()
        };
        tx.write(&mut is, &mut ()).unwrap();
        assert_eq!(hex::encode(&is.get_ref()), "01000000");
    }
}
