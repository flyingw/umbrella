use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use std::io;
use std::fmt;

#[derive(Default, PartialEq, Eq, Hash, Clone)]
/// Ethereum node `version`
pub struct NodeKey {
    pub version: Vec<u8>,
}

impl Serializable<NodeKey> for NodeKey {
    fn read(_reader: &mut dyn Read) -> Result<NodeKey> {
        Ok(NodeKey {version:vec![]})
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        // Endiannes?
        println!("WRITE THIS NODE KEY {:?}", self);
        writer.write(self.version.as_ref()).map(|_size| ())
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NodeKey")
            .field("version", &self.version)
            .finish()
    }
}