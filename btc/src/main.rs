use byteorder::{LittleEndian, BigEndian, WriteBytesExt, ReadBytesExt};
use log::{info};
use ring::digest;
use std::io;
use std::io::{Write, Read, Cursor};
use std::net::{TcpStream, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin::network::constants::Network;
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::consensus::encode::serialize;

fn main() {
  stderrlog::new().module(module_path!()).verbosity(2).init().unwrap();
  info!("starting");
  run().unwrap();
}

fn run() -> io::Result<()> {
  let mut stream = TcpStream::connect("127.0.0.1:18444")?;
  stream.set_nodelay(true)?;
  stream.set_read_timeout(None)?;
  info!("send version");
  // let magic: [u8; 4] = match network {
  //   Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
  //   Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
  //   Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
  // };
  let network = Network::Regtest;
  let magic = serialize(&network.magic());
  stream.write(&magic)?; // start string
  let command_name: [u8; 12] = *b"version\0\0\0\0\0";
  stream.write(&command_name)?; // command name
  let payload_size: usize = 86;
  stream.write_u32::<LittleEndian>(payload_size as u32)?; // payload size
  let mut payload = Vec::with_capacity(payload_size);
  payload.write_u32::<LittleEndian>(70015)?; // version
  payload.write_u64::<LittleEndian>(0)?; // services
  payload.write_i64::<LittleEndian>(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)?; // timestamp
  payload.write_u64::<LittleEndian>(0)?; // addr_recv services
  payload.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_recv IP address
  payload.write_u16::<BigEndian>(0)?; // addr_recv port
  payload.write_u64::<LittleEndian>(0)?; // addr_trans services
  payload.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_trans IP address
  payload.write_u16::<BigEndian>(0)?; // addr_trans port
  payload.write_u64::<LittleEndian>(0)?; // nonce
  payload.write_u8(0)?; // user_agent
  payload.write_i32::<LittleEndian>(0)?; // start_height
  payload.write_u8(0x01)?; // relay
  let hash = digest::digest(&digest::SHA256, payload.as_ref());
  let hash = digest::digest(&digest::SHA256, &hash.as_ref());
  let h = &hash.as_ref();
  let checksum = [h[0], h[1], h[2], h[3]];
  stream.write(&checksum)?; // checksum
  stream.write(&payload)?; // payload

  info!("read version");
  let mut p = vec![0; 24];
  stream.read_exact(p.as_mut())?;
  let mut c = Cursor::new(p);
  let mut magic1: [u8; 4] = Default::default();
  c.read(&mut magic1)?;
  info!("magic1={:?}", magic1);
  // todo assert magic == magic1

  let mut command_name1: [u8; 12] = Default::default();
  c.read(&mut command_name1)?;
  info!("command_name1={:?}", command_name1);
  // todo assert command == command_name

  let payload_size1 = c.read_u32::<LittleEndian>()?;
  info!("payload_size1={:?}", payload_size1);
  // todo assert payload_size1 <= 0x02000000 as u32 // 32 mb

  let mut checksum1: [u8; 4] = Default::default();
  c.read(&mut checksum1)?;
  info!("checksum1={:?}", checksum1);

  let mut p = vec![0; payload_size1 as usize];
  stream.read_exact(p.as_mut())?;
  info!("payload1={:?}", p);

  // todo validate checksum of payload

  // todo validate version (version, timestamp)

  info!("sending verack");
  let verack = serialize(&RawNetworkMessage { magic: network.magic(), payload: NetworkMessage::Verack });
  stream.write(&verack)?;

  info!("receiving verack");
  let mut p = vec![0; 24];
  stream.read_exact(p.as_mut())?;
  let mut c = Cursor::new(p);
  let mut magic1: [u8; 4] = Default::default();
  c.read(&mut magic1)?;
  info!("magic1={:?}", magic1);
  // todo assert magic == magic1

  let mut command_name1: [u8; 12] = Default::default();
  c.read(&mut command_name1)?;
  info!("command_name1={:?}", command_name1);
  // todo assert command == command_name

  let payload_size1 = c.read_u32::<LittleEndian>()?;
  info!("payload_size1={:?}", payload_size1);
  // todo assert payload_size1 == 0

  let mut checksum1: [u8; 4] = Default::default();
  c.read(&mut checksum1)?;
  info!("checksum1={:?}", checksum1);
  // todo assert checksum1 == 0x5df6e0e2

  info!("send tx"); //todo
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
