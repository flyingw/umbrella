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

    use rand::seq::SliceRandom;
    let seeds = network.seeds();
    let seed = seeds.choose(&mut rand::thread_rng()).unwrap();
    let seed = [&seed, ":", &network.port().to_string()].concat();

    use std::net::{SocketAddr, ToSocketAddrs};
    let seed: SocketAddr = seed.to_socket_addrs().unwrap().next().unwrap();
        
    let version = Version {
        version: PROTOCOL_VERSION,
        services: NODE_NONE, 
        timestamp: secs_since(UNIX_EPOCH) as i64,
        user_agent: "didactic".to_string(),
        ..Default::default()
    };

    let peer = Peer::connect(seed.ip(), seed.port(), network, version, 0, 0);
    peer.connected_event().poll();

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

    debug!{"transaction: {:#?}", tx};

    use messages::Message;

    peer.send(&Message::Tx(tx)).unwrap();

    // todo: put some small timeout to wait for response in error case.
    let response = peer.messages().poll();
    info!("resp: {:?}", response);
    peer.disconnect();
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
