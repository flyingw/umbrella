use bitcoin::consensus::encode::serialize;
use bitcoin::network::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::stream_reader::StreamReader;
use bitcoin::blockdata::transaction::{Transaction, OutPoint, TxIn, TxOut};
use bitcoin::blockdata::script::{Script, Builder};
use bitcoin::blockdata::opcodes;
use bitcoin::util::PublicKey;
use log::{info};
use std::io;
use std::io::{Write};
use std::net::{TcpStream, SocketAddr, IpAddr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use std::str::FromStr;

fn main() {
  stderrlog::new().module(module_path!()).verbosity(2).init().unwrap();
  info!("starting");
  run().unwrap();
}

fn run() -> io::Result<()> {
  // todo pass as parameter
  let mut stream = TcpStream::connect("127.0.0.1:18444")?;
  stream.set_nodelay(true)?;
  stream.set_read_timeout(None)?;
  let mut reader = StreamReader::new(stream.try_clone()?, None);
  // todo pass as parameter
  let network = Network::Regtest;

  info!("sending version");
  let ver = 70012; // 70015; todo support latest version
  let version = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Version(VersionMessage { version: ver, services: 0, timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64, receiver: Address::new(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0), 0), sender: Address::new(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0), 0), nonce: 0, user_agent: "".to_string(), start_height: 0, relay: true })});
  stream.write(&version)?;

  info!("reading version");
  info!("got={}", reader.next_message().expect("next message").command());

  info!("sending verack");
  let verack = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Verack });
  stream.write(&verack)?;

  info!("receiving verack");
  info!("got={}", reader.next_message().expect("next message").command());

  info!("sendng tx");
  // todo pass as parameter
  let outpoint = "6f0a111f0b3de8ab3a4defe8fc17272cc3c1076daa56acb856fd91a8114b7e7c:0"; // 50.0
  let secret = "cSs1ndPAmznGiboRm7Sv49ZhbpyYA3qAQQQhiWH8aWvRRRgssRQY" // todo pass secret aka private key
  let sig =  // todo pass sig of my address
  let pubkey = "0214e383d96aeaff716b681db281211a83240044945d952d8dd22fa00ff7bad316" // todo pass pubkey of my address
  let script_sig = Builder::new()
    .push_slice() // sig
    .push_key(&PublicKey::from_str(pubkey)) // pubkey
    .into_script();
  let txin = TxIn { previous_output: OutPoint::from_str(outpoint).expect("outpoint"), script_sig: script_sig, sequence: 0xFFFFFFFF, witness: vec![] };
  let script_pubkey1 = Builder::new()
    .push_opcode(opcodes::all::OP_DUP)
    .push_opcode(opcodes::all::OP_HASH160)
    .push_slice(&hex::decode("2NF4bh5ZjVdPiwsjoge41umHZHEBYMWGs9b").unwrap()) // todo pass new address
    .push_opcode(opcodes::all::OP_EQUALVERIFY)
    .push_opcode(opcodes::all::OP_CHECKSIG)
    .into_script();
  let txout1 = TxOut { value: 0, script_pubkey: script_pubkey1 };
  let fee = 10000 as u64; // todo parameter
  let amount = 5000000000 as u64; // todo parameter
  // todo change tx out
  // let txout2 = TxOut { value: amount-fee, script_pubkey: Script::new() };
  let tx = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Tx(Transaction { version: 1, lock_time: 0, input: vec![ txin ], output: vec![ txout1 ] })});
  stream.write(&tx)?;

  info!("got={}", reader.next_message().expect("next message").command());
  info!("got={}", reader.next_message().expect("next message").command());
  info!("got={}", reader.next_message().expect("next message").command());
  info!("got={}", reader.next_message().expect("next message").command());
  info!("got={}", reader.next_message().expect("next message").command());
  info!("got={}", reader.next_message().expect("next message").command());

  Ok(())
}
