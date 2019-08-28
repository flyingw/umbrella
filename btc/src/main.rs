use byteorder::{LittleEndian, BigEndian, WriteBytesExt, ReadBytesExt};
use log::{info};
use std::io;
use std::io::{Write, Read};
use std::net::{TcpStream, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
  stderrlog::new().module(module_path!()).verbosity(200).init().unwrap();
  info!("started");
  run().unwrap();
}

fn run() -> io::Result<()> {
  let mut stream = TcpStream::connect("127.0.0.1:18444")?;
  stream.set_nodelay(true)?;
  stream.set_nonblocking(false)?;
  stream.set_read_timeout(None)?;
  info!("send version");
  // https://bitcoin.org/en/developer-reference#version
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
  let mut stream = stream.try_clone()?;
  let mut xs = [0; 128];
  stream.read(&mut xs)?;
  info!("{}", xs[1]);
  // let version = stream.read_u32::<LittleEndian>()?;
  // info!("version={}", version);
  Ok(())
}
