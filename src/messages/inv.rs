use super::inv_vect::InvVect;
use super::message::Payload;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::result::{Error, Result};
use crate::serdes::Serializable;

/// Maximum number of objects in an inv message
pub const MAX_INV_ENTRIES: usize = 50000;

/// Inventory payload describing objects a node knows about
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct Inv {
    /// List of objects announced
    pub objects: Vec<InvVect>,
}

impl Serializable<Inv> for Inv {
    fn read(reader: &mut dyn Read) -> Result<Inv> {
        let num_objects = var_int::read(reader)? as usize;
        if num_objects > MAX_INV_ENTRIES {
            let msg = format!("Num objects exceeded maximum: {}", num_objects);
            return Err(Error::BadData(msg));
        }
        let mut objects = Vec::with_capacity(num_objects);
        for _ in 0..num_objects {
            objects.push(InvVect::read(reader)?);
        }
        Ok(Inv { objects })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.objects.len() as u64, writer)?;
        for object in self.objects.iter() {
            object.write(writer)?;
        }
        Ok(())
    }
}

impl Payload<Inv> for Inv {
    fn size(&self) -> usize {
        var_int::size(self.objects.len() as u64) + InvVect::SIZE * self.objects.len()
    }
}

impl fmt::Debug for Inv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.objects.len() <= 3 {
            f.debug_struct("Inv")
                .field("objects", &self.objects)
                .finish()
        } else {
            let s = format!("[<{} inventory vectors>]", self.objects.len());
            f.debug_struct("Inv").field("objects", &s).finish()
        }
    }
}
