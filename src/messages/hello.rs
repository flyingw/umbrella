use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use super::message::Payload;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Hello {
    data: Vec<u8>,
}

impl Serializable<Hello> for Hello{
    fn read(_reader: &mut dyn Read) -> Result<Hello> {
        panic!("can't read yet");
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        println!("write hello");
        writer.write_all(self.data.as_ref())
    }
}

impl Payload<Hello> for Hello {
    fn size(&self) -> usize {
        0
    }
}

impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hello")
            //.field("version", &self)
            .finish()
    }
}