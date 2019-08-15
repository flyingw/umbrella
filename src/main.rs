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
use bch::util::{secs_since,Amount, Hash256, Units};
use bch::util::rx::Observable;
use std::time::UNIX_EPOCH;
use std::net::{IpAddr, Ipv4Addr};

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
            hash: Hash256::decode("20a396c97db6158b11b4437a337279849ccfdb92b6e339b069cf06c9039c272c").unwrap(),
            index: 0,
        },
        sequence: 4294967295,
        sig_script: Script(hex::decode("483045022100c2c11e494efc98caf485a09d7166dfc5e1c1e8cfe2cf85d391ab59f2c360b90b022021ea942f67cb9f694108ed3798b2aec00e7c2bb328e62927473f4990b76e746d412103c0080bf04a431c8082fe9f67477f826e14406f20482759b59905a5035abec2f5").unwrap()),
    }];

    let outs = vec![TxOut{
        amount: Amount::from(0.3, Units::Bch),
        pk_script: Script(hex::decode("76a914926d53aeedc28d97d3819bf940ee303b94b9002c88ac").unwrap()),
    }, TxOut{
        amount: Amount::from(0.6999, Units::Bch),
        pk_script: Script(hex::decode("76a914e5216a352682217094f5d86b8d00188b02d1791e88ac").unwrap()),
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
