#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod address;
pub mod messages;
pub mod network;
pub mod peer;
pub mod script;
pub mod transaction;
pub mod util;
pub mod sighash;
pub mod hash256;
pub mod amount;
pub mod bits;
pub mod future;
pub mod hash160;
pub mod latch;
pub mod result;
pub mod rx;
pub mod serdes;
pub mod conf;
pub mod cashaddr;
pub mod var_int;
pub mod atomic_reader;
pub mod op_codes;
pub mod stack;
pub mod interpreter;

pub use serdes::Serializable;
pub use result::{Error, Result};
pub use amount::{Amount, Units};
pub use hash160::{Hash160, hash160};
pub use hash256::{sha256d, Hash256};
use conf::Opt;
use structopt::StructOpt;

use network::Network;
use messages::{Version, NODE_NONE, PROTOCOL_VERSION, Tx, TxIn, OutPoint, TxOut};
use messages::{Ping, Message,MessageHeader};
use peer::Peer;
use util::secs_since;
use rx::Observable;
use std::time::UNIX_EPOCH;

use script::Script;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sighash::{bip143_sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
use transaction::generate_signature;
use rust_base58::base58::FromBase58;

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
    let pub_script      = pk_script(&opt.sender.in_address);
    let chng_pk_script  = pk_script(&opt.sender.out_address);
    let dump_pk_script  = pk_script(&opt.data.dust_address);

    trace!("pk: {:?}", &pub_script);
    trace!("ck: {:?}", &chng_pk_script);
    trace!("dk: {:?}", &dump_pk_script);

    let mut tx = Tx {
        version: 2,
        inputs: vec![TxIn{
            prev_output: OutPoint {
                hash:  opt.sender.outpoint_hash,
                index: opt.sender.outpoint_index,
            },
            ..Default::default()
        }],
        outputs: vec![
            TxOut{ amount: Amount::from(opt.sender.change, Units::Bch), pk_script: chng_pk_script,}, 
            TxOut{ amount: Amount::from(opt.data.dust_amount, Units::Bch), pk_script: dump_pk_script, }],
        lock_time:0
    };

    let secp = Secp256k1::new();
    let mut cache = SigHashCache::new();
    
    let mut privk = [0;32];
    privk.copy_from_slice(&opt.sender.secret.from_base58().unwrap()[1..33]); 

    let secret_key = SecretKey::from_slice(&secp, &privk).expect("32 bytes, within curve order");
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

    trace!("secret: {:?} ", secret_key);
    trace!("public: {:?} ", hex::encode(&pub_key.serialize().as_ref()));

    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = bip143_sighash(&tx, 0, &pub_script.0, Amount::from(opt.sender.in_amount, Units::Bch), sighash_type, &mut cache).unwrap();
    let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    let sig_script = sig_script(&signature, &pub_key.serialize());

    tx.inputs[0].sig_script = sig_script;

    trace!{"transaction: {:#?}", tx};
    return tx;
}

///
/// Send transaction to selected network.
/// 
fn main() {
    let opt = Opt::from_args();
    
    stderrlog::new().module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbose)
        .modules(vec!("umbrella", "bch"))
        .init().unwrap();

    trace!("Options {:?}", opt);

    let network = opt.network;

    use rand::seq::{SliceRandom, IteratorRandom};

    let mut rng = rand::thread_rng();
    let seed = network.seeds();
    let seed = seed.choose(&mut rng).unwrap();
    let seed = [&seed, ":", &network.port().to_string()].concat();

    use std::net::{SocketAddr, ToSocketAddrs};
    let seed: SocketAddr = seed.to_socket_addrs().unwrap().choose(&mut rng).unwrap();

    use std::time::Duration;
    use std::net::{Shutdown,TcpStream};
    
    let mut stream = TcpStream::connect_timeout(&seed, Duration::from_secs(1)).unwrap();
    // + kind: ConnectionRefused for next seed
    stream.set_nodelay(true).unwrap();
    stream.set_nonblocking(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    
    let magic = network.magic();
    let mut partial: Option<MessageHeader> = None;
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
    
    our_version.write(&mut stream, magic).unwrap();

    use std::thread;
    use std::io;

    let lis = thread::spawn(move || {
        debug!("Connected {:?}", &seed);
        loop {
            let message = match &partial {
                Some(header) => Message::read_partial(&mut is, header),
                None => Message::read(&mut is, network.magic()),
            };

            match message {
                Ok(message) => {
                    if let Message::Partial(header) = message {
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
                                Message::Verack.write(&mut is, magic).unwrap();
                                // debug!("Write ping");
                                // Message::Ping(Ping {nonce: secs_since(UNIX_EPOCH) as u64,}).write(&mut is, magic).unwrap();
                            }
                            Message::Ping(ref ping) => {
                                debug!("Write {:#?}", ping);
                                Message::Pong(ping.clone()).write(&mut is, magic).unwrap();
                            }
                            Message::FeeFilter(ref fee) => {
                                debug!("min fee received {:?}", fee.minfee);
                                debug!("Write {:#?}", &tx);
                                tx.write(&mut is, magic).unwrap();
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
        Err(r) => {
            debug!("{:?}", r);
            stream.shutdown(Shutdown::Both).unwrap();
        }
    };

    // let pub_script      = pk_script(&opt.sender.in_address);
    // let chng_pk_script  = pk_script(&opt.sender.out_address);
    // let dump_pk_script  = pk_script(&opt.data.dust_address);

    // trace!("pk: {:?}", &pub_script);
    // trace!("ck: {:?}", &chng_pk_script);
    // trace!("dk: {:?}", &dump_pk_script);

    // let mut tx = Tx {
    //     version: 2,
    //     inputs: vec![TxIn{
    //         prev_output: OutPoint {
    //             hash:  opt.sender.outpoint_hash,
    //             index: opt.sender.outpoint_index,
    //         },
    //         ..Default::default()
    //     }],
    //     outputs: vec![
    //         TxOut{ amount: Amount::from(opt.sender.change, Units::Bch), pk_script: chng_pk_script,}, 
    //         TxOut{ amount: Amount::from(opt.data.dust_amount, Units::Bch), pk_script: dump_pk_script, }],
    //     lock_time:0
    // };

    // let secp = Secp256k1::new();
    // let mut cache = SigHashCache::new();
    
    // let mut privk = [0;32];
    // privk.copy_from_slice(&opt.sender.secret.from_base58().unwrap()[1..33]); 

    // let secret_key = SecretKey::from_slice(&secp, &privk).expect("32 bytes, within curve order");
    // let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

    // trace!("secret: {:?} ", secret_key);
    // trace!("public: {:?} ", hex::encode(&pub_key.serialize().as_ref()));

    // let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    // let sighash = bip143_sighash(&tx, 0, &pub_script.0, Amount::from(opt.sender.in_amount, Units::Bch), sighash_type, &mut cache).unwrap();
    // let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    // let sig_script = sig_script(&signature, &pub_key.serialize());

    // tx.inputs[0].sig_script = sig_script;

    // trace!{"transaction: {:#?}", tx};

    //use messages::Message;
    //peer.send(&Message::Tx(tx)).unwrap();
    // todo: put some small timeout to wait for response in error case.
    //let response = peer.messages().poll();
    //info!("resp: {:?}", response);
    //peer.disconnect();
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

        let secret_key = SecretKey::from_slice(&secp, &payload[..32]).expect("32 bytes, within curve order");
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        println!("sec: {:?}", secret_key);
        println!("pub: {:?}", hex::encode(&pub_key.serialize().as_ref()));
        
        // base32 over some bits
        let add = cashaddr_encode(&hash160(&pub_key.serialize()).0,  AddressType::P2PKH, Network::Regtest).unwrap();
        println!(" b32: {:?}", &add);

        assert_eq!("bchreg:qz68qweq3q8mt8xjspdawm0pfcq2pnxnkyucwhephh", add);
    }
}
