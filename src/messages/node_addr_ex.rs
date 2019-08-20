use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::node_addr::NodeAddr;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;

/// Node network address extended with a last connected time
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct NodeAddrEx {
    /// Last connected time in seconds since the unix epoch
    pub last_connected_time: u32,
    /// Node address
    pub addr: NodeAddr,
}

impl NodeAddrEx {
    /// Size of the NodeAddrEx in bytes
    pub const SIZE: usize = NodeAddr::SIZE + 4;

    /// Returns the size of the address in bytes
    pub fn size(&self) -> usize {
        NodeAddrEx::SIZE
    }
}

impl Serializable<NodeAddrEx> for NodeAddrEx {
    fn read(reader: &mut dyn Read) -> Result<NodeAddrEx> {
        Ok(NodeAddrEx {
            last_connected_time: reader.read_u32::<LittleEndian>()?,
            addr: NodeAddr::read(reader)?,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.last_connected_time)?;
        self.addr.write(writer)?;
        Ok(())
    }
}
