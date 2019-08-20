#[macro_use]
extern crate log;
extern crate stderrlog;

use ferris_says::say;
use std::io::{stdout, BufWriter};
use conf::Opt;
use structopt::StructOpt;

use bch::network::Network;
use bch::messages::{Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION, Tx, TxIn, OutPoint, TxOut};
use bch::peer::Peer;
use bch::util::{secs_since,Amount, Hash256, Units};
use bch::util::rx::Observable;
use std::time::UNIX_EPOCH;
use std::net::{IpAddr, Ipv4Addr};

use bch::script::Script;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use bch::transaction::sighash::{sighash, SigHashCache, SIGHASH_FORKID, SIGHASH_ALL};
use bch::transaction::generate_signature;
use rust_base58::base58::FromBase58;
use bch::transaction::p2pkh::{create_sig_script};

pub mod conf;

/// same functionality as in as create_pk_script. just to visualy trace op_codes here.
fn pk_script(addr: &str) -> Script {
    let mut s = Script::new();
    let mut payload = [1;20];

    use bch::address::cashaddr_decode;

    let hash = cashaddr_decode(addr, Network::Regtest).expect("correct cash address");
    payload.copy_from_slice(&hash.0[..20]);

    use bch::script::op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};

    s.append(OP_DUP);
    s.append(OP_HASH160);
    s.append_data(&payload);
    s.append(OP_EQUALVERIFY);
    s.append(OP_CHECKSIG);
    s   
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

    let (ip, port) = (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 18444);
        
    let version = Version {
        version: PROTOCOL_VERSION,
        services: NODE_BITCOIN_CASH, 
        timestamp: secs_since(UNIX_EPOCH) as i64,
        user_agent: "didactic".to_string(),
        ..Default::default()
    };

    let peer = Peer::connect(ip, port, Network::Regtest, version, 0, 0);
    peer.connected_event().poll();
    
    let pub_script      = pk_script("bchreg:qqsl42aquha5gz76fj99lk3ccq3dtyfa2g5857v8jc");
    let chng_pk_script  = pk_script("bchreg:qqt9nu7xp3myqv2rvuafse3wsqclnwdrtgrzy8t5dd");
    let dump_pk_script  = pk_script("bchreg:qqegtckkmttyclskd5jjz4fv0r7eucl42qqr6mpzrw");

    trace!("pk: {:?}", &pub_script);
    trace!("ck: {:?}", &chng_pk_script);
    trace!("dk: {:?}", &dump_pk_script);

    let mut tx = Tx {
        version: 2,
        inputs: vec![TxIn{
            prev_output: OutPoint {
                hash: Hash256::decode("ff8c7c3c77aa2e43932ad497cf0c8ba5a24f542ec1bcb7afe329a7166ae8dccd").unwrap(),
                index: 1,
            },
            ..Default::default()
        }],
        outputs: vec![
            TxOut{ amount: Amount::from(29.9997, Units::Bch), pk_script: chng_pk_script,}, 
            TxOut{ amount: Amount::from(0.0001, Units::Bch), pk_script: dump_pk_script, }],
        lock_time:0
    };

    let secret_wif = "cPubfVPWaF7dZv2Ppopq7rAeecnyxKDTfHjt3r2NNhpTwMZAdqWc";

    let secp = Secp256k1::new();
    let mut cache = SigHashCache::new();
    
    let mut privk = [0;32];
    privk.copy_from_slice(&secret_wif.from_base58().unwrap()[1..33]); 

    let secret_key = SecretKey::from_slice(&secp, &privk).expect("32 bytes, within curve order");
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

    debug!("secret: {:?} ", secret_key);
    debug!("public: {:?} ", hex::encode(&pub_key.serialize().as_ref()));

    let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
    let sighash = sighash(&tx, 0, &pub_script.0, Amount::from(29.9999, Units::Bch), sighash_type, &mut cache).unwrap();
    let signature = generate_signature(&privk, &sighash, sighash_type).unwrap();
    let sig_script = create_sig_script(&signature, &pub_key.serialize());

    tx.inputs[0].sig_script = sig_script;

    debug!{"transaction: {:#?}", tx};

    use bch::messages::Message;

    peer.send(&Message::Tx(tx)).unwrap();

    // todo: put some small timeout to wait for response in error case.
    let response = peer.messages().poll();
    info!("resp: {:?}", response);
    peer.disconnect();

    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());
    say(b"Hello fellow kids", 17, &mut writer).unwrap();
}

#[cfg(test)]
mod tests {
    // print some info with nocapture,
    // > cargo test -- --nocapture
    #[test] fn test_sail() {
        use super::*;
        use bch::util::sha256d;
        use bch::address::{AddressType,cashaddr_encode};
        use bch::network::Network;
        use rust_base58::base58::ToBase58;
        use bch::util::hash160;

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
