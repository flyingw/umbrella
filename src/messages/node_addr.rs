use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use crate::result::Result;
use crate::serdes::Serializable;


/// Network address for a node on the network
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddr {
    /// Services flags for the node
    pub services: u64,
    /// IPV6 address for the node. IPV4 addresses may be used as IPV4-mapped IPV6 addresses.
    pub ip: Ipv6Addr,
    /// Port for Bitcoin P2P communication
    pub port: u16,
}

impl NodeAddr {
    /// Size of the NodeAddr in bytes
    pub const SIZE: usize = 26;

    /// Creates a NodeAddr from an IP address and port
    pub fn new(ip: IpAddr, port: u16) -> NodeAddr {
        NodeAddr {
            services: 0,
            ip: match ip {
                IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
                IpAddr::V6(ipv6) => ipv6,
            },
            port,
        }
    }

    /// Returns the size of the address in bytes
    pub fn size(&self) -> usize {
        NodeAddr::SIZE
    }
}

impl Serializable<NodeAddr> for NodeAddr {
    fn read(reader: &mut dyn Read) -> Result<NodeAddr> {
        let services = reader.read_u64::<LittleEndian>()?;
        let mut ip = [0; 16];
        reader.read(&mut ip)?;
        let ip = Ipv6Addr::from(ip);
        let port = reader.read_u16::<BigEndian>()?;
        Ok(NodeAddr { services, ip, port })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(self.services)?;
        writer.write(&self.ip.octets())?;
        writer.write_u16::<BigEndian>(self.port)?;
        Ok(())
    }
}

impl Default for NodeAddr {
    fn default() -> NodeAddr {
        NodeAddr {
            services: 0,
            ip: Ipv6Addr::from([0; 16]),
            port: 0,
        }
    }
}
