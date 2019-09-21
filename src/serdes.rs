use std::io;
use std::io::{Read, Write};
use super::ctx::Ctx;
use super::result::Result;

/// An object that may be serialized and deserialized
pub trait Serializable<T> {
    /// Reads the object from serialized form
    fn read(reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<T>
    where
        Self: Sized;

    /// Writes the object to serialized form
    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()>;
}

impl Serializable<[u8; 16]> for [u8; 16] {
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<[u8; 16]> {
        let mut d = [0; 16];
        reader.read(&mut d)?;
        Ok(d)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write(self)?;
        Ok(())
    }
}

impl Serializable<[u8; 32]> for [u8; 32] {
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<[u8; 32]> {
        let mut d = [0; 32];
        reader.read(&mut d)?;
        Ok(d)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write(self)?;
        Ok(())
    }
}
