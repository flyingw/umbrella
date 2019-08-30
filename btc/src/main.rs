use byteorder::{LittleEndian, BigEndian, WriteBytesExt, ReadBytesExt};
use log::{info};
use ring::digest;
use std::io;
use std::io::{Write, Read, Cursor};
use std::net::{TcpStream, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

pub enum Network {
  Mainnet = 0,
  Testnet = 1,
  Regtest = 2,
}

fn main() {
  stderrlog::new().module(module_path!()).verbosity(2).init().unwrap();
  info!("starting");
  run(Network::Regtest).unwrap();
}

fn run(network: Network) -> io::Result<()> {
  let port = match network {
    Network::Mainnet => 8333,
    Network::Testnet => 18333,
    Network::Regtest => 18444,
  };
  let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
  stream.set_nodelay(true)?;
  stream.set_read_timeout(None)?;
  info!("send version");
  let magic: [u8; 4] = match network {
    Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
    Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
    Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
  };
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
  stream.write(&magic)?; // start string
  let command_name: [u8; 12] = *b"verack\0\0\0\0\0\0";
  stream.write(&command_name)?; // command name
  stream.write_u32::<LittleEndian>(0)?; // payload size
  stream.write(&[0x5d, 0xf6, 0xe0, 0xe2])?; // checksum

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

  Ok(())
}
