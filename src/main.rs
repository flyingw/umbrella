#[macro_use]
extern crate log;
extern crate stderrlog;

use ferris_says::say;
use std::io::{stdout, BufWriter};
use conf::Opt;
use structopt::StructOpt;

use bch::network::Network;
use bch::messages::{Message, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION, Tx, TxIn, OutPoint, TxOut};
use bch::peer::Peer;
use bch::util::{secs_since,hash160, Amount, Hash256, Units};
use bch::util::rx::Observable;
use std::time::UNIX_EPOCH;
use std::net::{IpAddr, Ipv4Addr};

use bch::script::op_codes::*;
use bch::script::Script;

pub mod conf;

/// Uses client library to connect to network pear and send some message
/// But needs to have own p2p infrastructure and sign the transactions :)
fn main() {
    let opt = Opt::from_args();
    
    stderrlog::new().module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbose)
        .modules(vec!("didactic_umbrella", "bch"))
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
    
    let ins = vec![TxIn{
        prev_output: OutPoint {
            hash: Hash256::decode("7375c75c2b24e6e51a71f912ed61e937e70c7fcf7d1008229b87e26555e23e8a").unwrap(),
            index: 1,
        },
        sequence: 4294967295,
        sig_script: Script(hex::decode("47304402200a7866430b70da3a8abf03b5e3711abcc5c926ac05ff3f274dd1c0ad317cc74d022050bcf0e4a0dc424644d4f7d90360cfdcca845e4dbdaf0ae0484b363f1b157d5c41210262cb2c04df5b31574df9568aa9a5c8e02b5b82fa4813e69a1bc7ac15d2042d93").unwrap()),
    }];

    let outs = vec![TxOut{
        amount: Amount::from(1., Units::Bch),
        pk_script: Script(hex::decode("76a9146e3c0d8fe75ef9c8dcd49be1c3d3f4d790ed8ce388ac").unwrap()),
    }, TxOut{
        amount: Amount::from(7.9998, Units::Bch),
        pk_script: Script(hex::decode("76a91478854a9b95b7672d9011ed690f8677ee5bad8b0288ac").unwrap()),
    }];

    let tx = Tx {
        version: 2,
        inputs: ins,
        outputs: outs,
        lock_time:0
    };

    let tr = Message::Tx(tx);
    peer.send(&tr).unwrap();

    let response = peer.messages().poll();
    info!("resp: {:?}", response);

    peer.disconnect();

    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());
    say(b"Hello fellow kids", 17, &mut writer).unwrap();
}

#[cfg(test)]
mod tests {
    #[test] fn test_sail() { assert_eq!(1, 1) }
}
