use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use super::message::Payload;
use super::node_addr::NodeAddr;
use std::io;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;
use crate::var_int;
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::util::secs_since;
use crate::ctx::Ctx;

/// Protocol version supported by this library
pub const PROTOCOL_VERSION: u32 = 70015;

/// Minimum protocol version supported by this library
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 70001;

/// Service flag that node is not a full node. Used for SPV wallets.
pub const NODE_NONE: u64 = 0;

/// Version payload defining a node's capabilities
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone)]
pub struct Version {
    /// The protocol version being used by the node
    pub version: u32,
    /// Bitfield of features to be enabled for this connection
    pub services: u64,
    /// Time since the Unix epoch in seconds
    pub timestamp: i64,
    /// Network address of the node receiving this message
    pub recv_addr: NodeAddr,
    /// Network address of the node emitting this message
    pub tx_addr: NodeAddr,
    /// A random nonce which can help a node detect a connection to itself
    pub nonce: u64,
    /// User agent string
    pub user_agent: String,
    /// Height of the transmiting node's best block chain, or in the case of SPV wallets, block header chain
    pub start_height: i32,
    /// Whether the client wants to receive broadcast transactions before a filter is set
    pub relay: bool,
}

impl Version {
    /// Checks if the version message is valid
    pub fn validate(&self) -> Result<()> {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION {
            let msg = format!("Unsupported protocol version: {}", self.version);
            return Err(Error::BadData(msg));
        }
        let now = secs_since(UNIX_EPOCH) as i64;
        if (self.timestamp - now).abs() > 2 * 60 * 60 {
            let msg = format!("Timestamp too old: {}", self.timestamp);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }
}

impl Serializable<Version> for Version {
    fn read(reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<Version> {
        let mut ret = Version {
            ..Default::default()
        };
        ret.version = reader.read_u32::<LittleEndian>()?;
        ret.services = reader.read_u64::<LittleEndian>()?;
        ret.timestamp = reader.read_i64::<LittleEndian>()?;
        ret.recv_addr = NodeAddr::read(reader, ctx)?;
        ret.tx_addr = NodeAddr::read(reader, ctx)?;
        ret.nonce = reader.read_u64::<LittleEndian>()?;
        let user_agent_size = var_int::read(reader)? as usize;
        let mut user_agent_bytes = vec![0; user_agent_size];
        reader.read(&mut user_agent_bytes)?;
        ret.user_agent = String::from_utf8(user_agent_bytes)?;
        ret.start_height = reader.read_i32::<LittleEndian>()?;
        ret.relay = reader.read_u8()? == 0x01;
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write,ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write_u32::<LittleEndian>(self.version)?;
        writer.write_u64::<LittleEndian>(self.services)?;
        writer.write_i64::<LittleEndian>(self.timestamp)?;
        self.recv_addr.write(writer, ctx)?;
        self.tx_addr.write(writer, ctx)?;
        writer.write_u64::<LittleEndian>(self.nonce)?;
        var_int::write(self.user_agent.as_bytes().len() as u64, writer)?;
        writer.write(&self.user_agent.as_bytes())?;
        writer.write_i32::<LittleEndian>(self.start_height)?;
        writer.write_u8(if self.relay { 0x01 } else { 0x00 })?;
        Ok(())
    }
}

impl Payload<Version> for Version {
    fn size(&self) -> usize {
        33 + self.recv_addr.size()
            + self.tx_addr.size()
            + var_int::size(self.user_agent.as_bytes().len() as u64)
            + self.user_agent.as_bytes().len()
    }
}
