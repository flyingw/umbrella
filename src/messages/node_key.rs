use std::io::{Read, Write};
use super::message::Payload;
use crate::ctx::Ctx;
use crate::result::Result;
use crate::serdes::Serializable;
use std::io;
use std::fmt;
use hex;

#[derive(Default, PartialEq, Eq, Hash, Clone)]
/// Ethereum node `version`
pub struct NodeKey {
    pub version: Vec<u8>,
}

impl Serializable<NodeKey> for NodeKey {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<NodeKey> { panic!("not supposed to be read") }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write(self.version.as_ref()).map(|_size| ())
    }
}

impl Payload<NodeKey> for NodeKey {
    fn size(&self) -> usize {
        self.version.len()
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Our 'node' PubKey: {:x?}", hex::encode(&self.version))
    }
}