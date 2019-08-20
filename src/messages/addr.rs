use super::message::Payload;
use super::node_addr_ex::NodeAddrEx;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::var_int;
use crate::serdes::Serializable;

/// Maximum number of addresses allowed in an Addr message
const MAX_ADDR_COUNT: u64 = 1000;

/// Known node addresses
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Addr {
    /// List of addresses of known nodes
    pub addrs: Vec<NodeAddrEx>,
}

impl Serializable<Addr> for Addr {
    fn read(reader: &mut dyn Read) -> Result<Addr> {
        let mut ret = Addr { addrs: Vec::new() };
        let count = crate::var_int::read(reader)?;
        if count > MAX_ADDR_COUNT {
            let msg = format!("Too many addrs: {}", count);
            return Err(Error::BadData(msg));
        }
        for _i in 0..count {
            ret.addrs.push(NodeAddrEx::read(reader)?);
        }
        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.addrs.len() as u64, writer)?;
        for item in self.addrs.iter() {
            item.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Addr> for Addr {
    fn size(&self) -> usize {
        var_int::size(self.addrs.len() as u64) + self.addrs.len() * NodeAddrEx::SIZE
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.addrs.len() <= 3 {
            f.debug_struct("Addr").field("addrs", &self.addrs).finish()
        } else {
            let s = format!("[<{} addrs>]", self.addrs.len());
            f.debug_struct("Addr").field("addrs", &s).finish()
        }
    }
}
