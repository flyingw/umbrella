use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use log::{info};
use ring::digest;
use std::io;
use std::io::{Write, Read};
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
  stream.set_nonblocking(false)?;
  stream.set_read_timeout(None)?;
  info!("send version");
  let magic: [u8; 4] = match network {
    Network::Mainnet => [0xe3, 0xe1, 0xf3, 0xe8],
    Network::Testnet => [0xf4, 0xe5, 0xf3, 0xf4],
    Network::Regtest => [0xda, 0xb5, 0xbf, 0xfa],
  };
  stream.write(&magic)?; // start string
  let command_name: [u8; 12] = *b"version\0\0\0\0\0";
  stream.write(&command_name)?; // command name
  let payload_size: usize = 86;
  stream.write_u32::<LittleEndian>(payload_size as u32)?; // payload size
  let mut payload = Vec::with_capacity(payload_size);
  // 4+8+8+8+2+2+8+2+2+8+1+4+1
  payload.write_u32::<LittleEndian>(70015)?; // version 4
  payload.write_u64::<LittleEndian>(0)?; // services 8
  payload.write_i64::<LittleEndian>(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)?; // timestamp 8
  payload.write_u64::<LittleEndian>(0)?; // addr_recv services 8
  payload.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_recv IP address 2
  payload.write_u16::<BigEndian>(0)?; // addr_recv port 2
  payload.write_u64::<LittleEndian>(0)?; // addr_trans services 8
  payload.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_trans IP address 2
  payload.write_u16::<BigEndian>(0)?; // addr_trans port 2
  payload.write_u64::<LittleEndian>(0)?; // nonce 8
  payload.write_u8(0)?; // user_agent 1
  payload.write_i32::<LittleEndian>(0)?; // start_height 4
  payload.write_u8(0x01)?; // relay 1
  let hash = digest::digest(&digest::SHA256, payload.as_ref());
  let hash = digest::digest(&digest::SHA256, &hash.as_ref());
  let h = &hash.as_ref();
  let checksum = [h[0], h[1], h[2], h[3]];
  stream.write(&checksum)?; // checksum
  stream.write_u32::<LittleEndian>(70015)?; // version
  stream.write_u64::<LittleEndian>(0)?; // services
  stream.write_i64::<LittleEndian>(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)?; // timestamp
  stream.write_u64::<LittleEndian>(0)?; // addr_recv services
  stream.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_recv IP address
  stream.write_u16::<BigEndian>(0)?; // addr_recv port
  stream.write_u64::<LittleEndian>(0)?; // addr_trans services
  stream.write(&Ipv6Addr::from([0; 16]).octets())?; // addr_trans IP address
  stream.write_u16::<BigEndian>(0)?; // addr_trans port
  stream.write_u64::<LittleEndian>(0)?; // nonce
  stream.write_u8(0)?; // user_agent
  stream.write_i32::<LittleEndian>(0)?; // start_height
  stream.write_u8(0x01)?; // relay

  info!("read version");
  // let mut p = vec![0; 24];
  // stream.read_exact(p.as_mut())?;
  // info!("header={:?}", p);
  // let mut   bytes = stream.try_clone()?;
  // let mut xs = [0; 128];
  // let mut buffer = String::new();
  // stream.read_to_string(&mut buffer)?;
  // info!("={}=", buffer);
  // let version = stream.read_u32::<LittleEndian>()?;
  // info!("version={}", version);
  Ok(())
}
