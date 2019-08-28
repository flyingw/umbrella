use byteorder::{LittleEndian, BigEndian, WriteBytesExt};
use log::{info};
use std::io;
use std::io::Write;
use std::net::{TcpStream, Ipv6Addr};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

fn main() {
  stderrlog::new().module(module_path!()).verbosity(2).init().unwrap();
  info!("started");
  run().unwrap();
}

fn run() -> io::Result<()> {
  let mut stream = TcpStream::connect("127.0.0.1:18444")?;
  info!("send version");
  // https://bitcoin.org/en/developer-reference#version
  stream.write_u32::<LittleEndian>(70015)?; // version
  stream.write_u64::<LittleEndian>(0)?; // services
  stream.write_i64::<LittleEndian>(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64)?; // timestamp
  stream.write_u64::<LittleEndian>(0)?;
  stream.write(&Ipv6Addr::from([0; 16]).octets())?;
  stream.write_u16::<BigEndian>(0)?;
  Ok(())
}
