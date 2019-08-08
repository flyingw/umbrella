#[macro_use]
extern crate log;
extern crate stderrlog;

use ferris_says::say;
use std::io::{stdout, BufWriter};
use conf::Opt;
use structopt::StructOpt;

use bch::network::Network;
use bch::messages::{Message, Ping, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
use bch::peer::Peer;
use bch::util::secs_since;
use bch::util::rx::Observable;
use std::time::UNIX_EPOCH;
use std::net::{IpAddr, Ipv4Addr};

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

    let ping = Message::Ping(Ping { nonce: 0 });
    peer.send(&ping).unwrap();

    let response = peer.messages().poll();
    info!("{:?}", response);

    peer.disconnect();

    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());
    say(b"Hello fellow kids", 17, &mut writer).unwrap();
}

#[cfg(test)]
mod tests {
    #[test] fn test_sail() { assert_eq!(1, 1) }
}
