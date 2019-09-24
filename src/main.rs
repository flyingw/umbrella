#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

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
pub mod hashu256;
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

mod connection;

pub use serdes::Serializable;
pub use result::{Error, Result};
pub use amount::{Amount, Units};
pub use hash160::{Hash160, hash160};
pub use hash256::{sha256d, Hash256};
use conf::Opt;
use structopt::StructOpt;

use network::Network;
use messages::{Version, NODE_NONE, PROTOCOL_VERSION, Tx, TxIn, OutPoint, TxOut, NodeKey, Hello, Reject, RejectCode};
use messages::{Message,MsgHeader};
use util::secs_since;
use std::time::{UNIX_EPOCH, Duration};
use script::Script;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sighash::{bip143_sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
use transaction::generate_signature;
use rust_base58::base58::FromBase58;
use aes_ctr::Aes256Ctr;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes_ctr::stream_cipher::NewStreamCipher;

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

fn create_transaction(opt: &Opt) -> Tx {
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

    trace!("secret: {:?} ", secret_key);
    trace!("public: {:?} ", hex::encode(&pub_key.serialize().as_ref()));

    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = bip143_sighash(&mut tx, 0, &pub_script.0, Amount::from(opt.sender().in_amount(), Units::Bch), sighash_type, &mut cache).unwrap();
    let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    let sig_script = sig_script(&signature, &pub_key.serialize());

    tx.inputs[0].sig_script = sig_script;

    trace!{"transaction: {:#?}", tx};
    return tx;
}

///
/// Send transaction to selected network.
/// 
pub fn main1() {
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
    stream.set_nodelay(true).unwrap();
    stream.set_nonblocking(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    
    let magic = network.magic();
    let mut partial: Option<Box<dyn MsgHeader>> = None;
    let mut is = stream.try_clone().unwrap();
    
    let tx = Message::Tx(create_transaction(&opt));

    let version = Version {
        version: PROTOCOL_VERSION,
        services: NODE_NONE, 
        timestamp: secs_since(UNIX_EPOCH) as i64,
        user_agent: "didactic".to_string(),
        ..Default::default()
    };

    let our_version = Message::Version(version);
    debug!("Write {:#?}", our_version);
    
    our_version.write(&mut stream, magic, &mut ()).unwrap();

    use std::io;
    let mut ct = ();

    let lis = thread::spawn(move || {
        debug!("Connected {:?}", &seed);
        loop {
            let message = match &partial {
                Some(header) => Message::read_partial(&mut is, header.as_ref(), &mut ct),
                None => Message::read(&mut is, network.magic(), &mut ct),
            };

            match message {
                Ok(message) => {
                    if let Message::Partial( header) = message {
                        partial = Some(header);
                    } else {
                        partial = None;
                        println!("message: {:?}", message);

                        match message {
                            Message::Version(v) => {
                                debug!("Version {:?}, verract", v);
                            }
                            Message::Verack => {
                                debug!("Write {:#?}", Message::Verack);
                                Message::Verack.write(&mut is, magic, &mut ()).unwrap();
                                // debug!("Write ping");
                                // Message::Ping(Ping {nonce: secs_since(UNIX_EPOCH) as u64,}).write(&mut is, magic).unwrap();
                            }
                            Message::Ping(ref ping) => {
                                debug!("Write {:#?}", ping);
                                Message::Pong(ping.clone()).write(&mut is, magic, &mut ()).unwrap();
                            }
                            Message::FeeFilter(ref fee) => {
                                debug!("min fee received {:?}", fee.minfee);
                                debug!("Write {:#?}", &tx);
                                tx.write(&mut is, magic, &mut ()).unwrap();
                                return Ok(tx);
                            }
                            Message::Reject(ref reject) => {
                                debug!("rejected {:?}", reject);
                                return Ok(Message::Reject(reject.clone()));
                            }
                            _ => {
                                debug!("not handled {:?}",  message);
                            }
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

    match lis.join() {
        Ok(v)  => debug!("{:?}", v),
        Err(r) => debug!("{:?}", r),
    };

    use std::net::Shutdown;
    stream.shutdown(Shutdown::Both).unwrap();
}

use common_types::transaction::{Transaction, Action};
use ethereum_types::{U256};
use ethkey::Address;
use std::str::FromStr;
use std::thread;
use ethstore::Crypto;
use ethkey::Password;
use crate::messages::commands;

use connection::{OriginatedEncryptedConnection};

/// 
fn main() {
    let opt = Opt::from_args();

    stderrlog::new().module(module_path!())
        .quiet(opt.quiet)
        .verbosity(4)
        .modules(vec!("umbrella", "eth"))
        .init().unwrap();

    trace!("Options {:?}", opt);

    use rand::seq::{SliceRandom, IteratorRandom};
    let mut rng = rand::thread_rng();

    let network = opt.network.network();
    let seed = network.seeds();
    let seed = seed.choose(&mut rng).unwrap();
    let seed = [&seed, ":", &network.port().to_string()].concat();

    let pub_key = opt.sender().pub_key();
    use crate::keys::slice_to_public;
    let pub_key:PublicKey = slice_to_public(&pub_key).unwrap();

    use std::net::{SocketAddr, ToSocketAddrs};
    let seed: SocketAddr = seed.to_socket_addrs().unwrap().choose(&mut rng).unwrap();

    let secret: Secret = match opt.sender().crypto() {
        Some(ref s) => {
            let cry: Crypto = Crypto::from_str(s).unwrap();
            let password = Password::from(opt.sender().password());
            cry.secret(&password).unwrap()
        }
        None => Secret::from_str(&opt.sender().secret().unwrap()).unwrap(),
    };

    trace!("secret: {:?}", secret);
    trace!("pubkey: {:?}", pub_key);
    trace!("seed node: {:?}", seed);

    use tiny_keccak::Keccak;
    use ethkey::crypto::{ecdh, ecies};
    use crate::keys::public_to_slice;
    use ethkey::{sign, Secret, Public};
    use ethereum_types::H256;

    let nonce: Hash256 = Hash256::random();
    let secp = Secp256k1::new();
    
    //handshake write
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let public_key_slice = public_to_slice(&public_key);
    let secret = Secret::from_slice(&secret_key[0..32]).unwrap();

    let (ecdhe_secret_key, ecdhe_public_key) = secp.generate_keypair(&mut rng);
    let ecdhe_public_key_slice = public_to_slice(&ecdhe_public_key);
    let ecdhe_secret = Secret::from_slice(&ecdhe_secret_key[0..32]).unwrap();

    let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1]; //TODO: use associated constants
    let data_len = data.len();
    
    data[data_len - 1] = 0x0;
    let (sig, rest) = data.split_at_mut(65);
    let (hepubk, rest) = rest.split_at_mut(32);
    let (pubk, rest) = rest.split_at_mut(64);
    let (data_nonce, _) = rest.split_at_mut(32);

    // E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) || H(ecdhe-random-pubk) || pubk || nonce || 0x0)
    let node_key = Public::from_slice(&public_to_slice(&pub_key));
    let shared: H256 = *ecdh::agree(&secret, &node_key).unwrap();

    let xor = Hash256::from_slice(shared.as_bytes()) ^ nonce;
    sig.copy_from_slice(&*sign(&ecdhe_secret, &H256::from_slice(xor.as_bytes())).unwrap());
    Keccak::keccak256(&ecdhe_public_key_slice, hepubk);
    pubk.copy_from_slice(&public_key_slice);
    data_nonce.copy_from_slice(nonce.as_bytes());
    
    let message: Vec<u8> = ecies::encrypt(&node_key, &[], &data).unwrap();
    let auth_cipher: Vec<u8> = message.clone();
    
    use std::net::TcpStream;

    let mut stream = TcpStream::connect_timeout(&seed, Duration::from_secs(1)).unwrap();
    let is = stream.try_clone().unwrap();
    let magic = network.magic();

    debug!("Network magic: {:?}", magic);

    let version = NodeKey {
        version: message
    };
    
    let ctx = &mut ();
    let our_version = Message::NodeKey(version);
    debug!("Write {:#?}", our_version);
    our_version.write(&mut stream, magic, ctx).unwrap();

    //handshake read
    use std::io::Read;
    let mut data: Vec<u8> = vec![0u8; connection::RLPX_TRANSPORT_AUTH_ACK_PACKET_SIZE_V4];
	stream.read_exact(data.as_mut_slice()).unwrap();

    let ack_cipher: Vec<u8> = data.clone().to_vec();
    let mut connection = ecies::decrypt(&secret, &[], &data).map(|ack| {
        use crate::hash512::Hash512;
        use crate::connection::NULL_IV;

        let mut remote_ephemeral: Public = Public::default();
        let mut remote_nonce: Hash256 = Hash256::default();

        remote_ephemeral.assign_from_slice(&ack[0..64]);
        remote_nonce.copy_from_slice(&ack[64..(64+32)]);		

        let ecdhe_secret = Secret::from_slice(&ecdhe_secret_key[0..32]).unwrap();
		let shared = ecdh::agree(&ecdhe_secret, &remote_ephemeral).unwrap();
		let mut nonce_material = Hash512::default();
		(&mut nonce_material[0..32]).copy_from_slice(remote_nonce.as_bytes());
		(&mut nonce_material[32..64]).copy_from_slice(nonce.as_bytes());
		let mut key_material = Hash512::default();
		(&mut key_material[0..32]).copy_from_slice(shared.as_bytes());
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

		let mut ingress_mac = Keccak::new_keccak256();
		mac_material = Hash256::from_slice(&key_material[32..64]) ^ nonce;
		ingress_mac.update(mac_material.as_bytes());
		ingress_mac.update(&ack_cipher);

        
		OriginatedEncryptedConnection {
			stream: is,
			encoder: encoder,
			decoder: decoder,
			mac_encoder_key: mac_encoder_key,
			egress_mac: egress_mac,
			ingress_mac: ingress_mac,
			public_key: public_key,
            expected: commands::HELLO,
		}
    }).unwrap();

    use rlp::RlpStream;

    const PACKET_USER: u8 = 0x10;
    const PACKET_TRANSACTIONS: u8 = 0x02 + PACKET_USER;
    
    let hello = Hello {
        public_key: public_key,
    };

    trace!("write out hello");
    let our_hello = Message::Hello(hello);
    our_hello.write(&mut stream, magic, &mut connection).unwrap();

    let mut partial: Option<Box<dyn MsgHeader>> = None;
    use std::io;
    //use std::io::Cursor;
    use std::convert::TryInto;

    let mut os = stream.try_clone().unwrap();

    let lis = thread::spawn(move || {
        debug!("Connected {:?}", &seed);
            loop {
            debug!("read partial shit ");
            let message = match &partial {
                Some(header) => Message::read_partial(&mut os, header.as_ref(), &mut connection),
                None => Message::read2(&mut os, magic[..3].try_into().expect("shortened magic"), &mut connection),
            };

            match message {
                Ok(message) => {
                    if let Message::Partial( header) = message {
                        partial = Some(header);
                    } else {
                        partial = None;
                        println!("message: {:?}", message);
                        match message {
                            Message::Hello(hello) => {
                                debug!("HELLO {:?}", &hello);
                                connection.expected = commands::STATUS;
                                //return Ok(Message::Hello(hello.clone()));
                                //we should't return here but 
                            }
                            Message::Status(status) => {
                                debug!("STATUS {:?}", &status);
                                debug!("write that shit back");
                                status.write(&mut os, &mut connection).unwrap();

                                debug!("Write transaction after status");
                                //
                                let t = Transaction {
                                    nonce: U256::from(2),
                                    gas_price: U256::from(1_000_000_000u64),
                                    gas: U256::from(21_000),
                                    action: Action::Call(Address::from_str(&opt.sender().out_address()).unwrap()),
                                    value: U256::from(10),
                                    data: Vec::new(),
                                };
                                let singed_transaction = t.sign(&secret, Some(123));

                                //protocol.write_transactions(&vec![&singed_transaction]);
                                let transactions = &vec![&singed_transaction];
                                let mut rlp = RlpStream::new_list(transactions.len());
                                for t in transactions {
                                    rlp.append(*t);
                                }
                                let data = &rlp.out();
                                let mut rlp = RlpStream::new();
                                rlp.append(&(u32::from(PACKET_TRANSACTIONS)));
                                let mut compressed = Vec::new();
                                let len = parity_snappy::compress_into(data, &mut compressed);
                                let payload = &compressed[0..len];
                                rlp.append_raw(payload, 1);
                                connection.write_packet(&rlp.out()).unwrap();

                                debug!("transaction : {:?}", singed_transaction);
                                debug!("        hash: {:?}", singed_transaction.hash());
                                return Ok(Message::Tx2(singed_transaction));
                            }
                            _ => {
                                debug!("Some other shit {:?}", message);
                                return Ok(Message::Reject(Reject{
                                    message: "String".to_string(),
                                    code: RejectCode::RejectMalformed,
                                    reason: "String".to_string(),
                                    data: vec![],
                                    }
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Error::IOError(ref e) = e {
                            if e.kind() == io::ErrorKind::WouldBlock || 
                                e.kind() == io::ErrorKind::TimedOut {
                                debug!("continue");
                                continue;
                            }
                    }
                    return Err(e);
                }
            }
        }
    });

    match lis.join() {
        Ok(v)  => debug!("{:?}", v),
        Err(r) => debug!("{:?}", r),
    };

    //use messages::SecHeader;
    //let header = SecHeader::read(&mut stream, &mut connection).unwrap();
    //let payload = header.payload(&mut stream, &mut connection).unwrap();
    //let hello = Hello::read(&mut Cursor::new(payload), &mut connection).unwrap();
    //println!("read hello={:?}", &hello);
    
    //panic!("enough");
    //use messages::Status;
    //let header = SecHeader::read(&mut stream, &mut connection).unwrap();
    //let payload = header.payload(&mut stream, &mut connection).unwrap();
    //let status = Status::read(&mut Cursor::new(payload), &mut connection).unwrap();
    //println!("read status={:?}", &status);

    //status.write(&mut stream, &mut connection).unwrap();
    //println!("write status={:?}", &status);

}

#[cfg(test)]
mod tests {
    // print some info with nocapture,
    // > cargo test -- --nocapture
    #[test] fn test_sail() {
        use super::*;
        //use sha256::sha256d;
        use address::AddressType;
        use cashaddr::cashaddr_encode;
        use network::Network;
        use rust_base58::base58::ToBase58;
        use hash160;

        let secret_wif: &str = &"cPSW2teJFwABTyvxrE39VuX3PGTUm1kkFhtzHXLqv6BzaUxT7PzF";
        println!("wif: {:?}", secret_wif);
        let b58 = secret_wif.from_base58().unwrap();        
        let check_sum = &b58[34..];
        let payload = &b58[1..33];
        println!("b58: {:?}", b58);
        println!("b58: {:?}", &b58.to_base58());
        println!("1st: {:?}", &b58[0]);
        println!(" 33: {:?}", &b58[1..34]);
        println!("pld: {:?}", payload);
        println!("cmp: {:?}", &b58[33]); // last byte is about compression and should be dropped
        println!("chk: {:?}", check_sum);

        assert_eq!(check_sum, &sha256d(&b58[..34]).0[..4]);

        let secp = Secp256k1::new();

        let secret_key = SecretKey::from_slice(&payload[..32]).expect("32 bytes, within curve order");
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        println!("sec: {:?}", secret_key);
        println!("pub: {:?}", hex::encode(&pub_key.serialize().as_ref()));
        
        // base32 over some bits
        let add = cashaddr_encode(&hash160(&pub_key.serialize()).0,  AddressType::P2PKH, Network::Regtest).unwrap();
        println!(" b32: {:?}", &add);

        assert_eq!("bchreg:qz68qweq3q8mt8xjspdawm0pfcq2pnxnkyucwhephh", add);
    }
}
