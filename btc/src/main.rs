use log::{info};
use std::io;
use std::io::{Write};
use std::net::{TcpStream, SocketAddr, IpAddr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin::network::constants::Network;
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::address::Address;
use bitcoin::consensus::encode::serialize;
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::stream_reader::StreamReader;

fn main() {
  stderrlog::new().module(module_path!()).verbosity(2).init().unwrap();
  info!("starting");
  run().unwrap();
}

fn run() -> io::Result<()> {
  let mut stream = TcpStream::connect("127.0.0.1:18444")?;
  stream.set_nodelay(true)?;
  stream.set_read_timeout(None)?;
  let mut reader = StreamReader::new(stream.try_clone()?, None);
  let network = Network::Regtest;

  info!("sending version");
  let version = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Version(VersionMessage { version: 70015, services: 0, timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64, receiver: Address::new(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0), 0), sender: Address::new(&SocketAddr::new(IpAddr::V6(Ipv6Addr::from([0; 16])), 0), 0), nonce: 0, user_agent: "".to_string(), start_height: 0, relay: true })});
  stream.write(&version)?;

  info!("reading version");
  info!("got={}", reader.next_message().expect("next message").command());

  info!("sending verack");
  let verack = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Verack });
  stream.write(&verack)?;

  info!("receiving verack");
  info!("got={}", reader.next_message().expect("next message").command());

  // info!("sendng tx"); //todo
  // stream.write(&magic)?; // start string
  // let command_name: [u8; 12] = *b"tx\0\0\0\0\0\0\0\0\0\0";
  // stream.write(&command_name)?; // command name
  // let payload_size: usize = ???;
  // // validate payload size?
  // stream.write_u32::<LittleEndian>(payload_size as u32)?; // payload size
  // let mut payload = Vec::with_capacity(payload_size);
  // payload.write_u32::<LittleEndian>(1)?; // version
  // payload.write_u8(1 as u8)?; // tx_in count
  // // tx_in: previous_output: hash
  // // tx_in: previous_output: index
  // // tx_in: script bytes
  // // tx_in: signature script
  // // tx_in: sequence
  // payload.write_u8(1 as u8)?; // tx_out count
  // // tx_out: value
  // // tx_out: pk_script bytes
  // // tx_out: pk_script
  // payload.write_u32::<LittleEndian>(0)?; // lock_time

  // let hash = digest::digest(&digest::SHA256, payload.as_ref());
  // let hash = digest::digest(&digest::SHA256, &hash.as_ref());
  // let h = &hash.as_ref();
  // let checksum = [h[0], h[1], h[2], h[3]];
  // stream.write(&checksum)?; // checksum
  // stream.write(&payload)?; // payload

  Ok(())
}
