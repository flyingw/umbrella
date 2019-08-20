use hex;
use super::message::Payload;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::var_int;
use crate::serdes::Serializable;

/// Maximum size of a data element in the FilterAdd message
pub const MAX_FILTER_ADD_DATA_SIZE: usize = 520;

/// Adds a data element to the bloom filter
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct FilterAdd {
    /// Data element to be added
    pub data: Vec<u8>,
}

impl FilterAdd {
    /// Returns whether the FilterAdd message is valid
    pub fn validate(&self) -> Result<()> {
        if self.data.len() > MAX_FILTER_ADD_DATA_SIZE {
            return Err(Error::BadData("Data too long".to_string()));
        }
        Ok(())
    }
}

impl Serializable<FilterAdd> for FilterAdd {
    fn read(reader: &mut dyn Read) -> Result<FilterAdd> {
        let data_len = var_int::read(reader)?;
        let mut data = vec![0; data_len as usize];
        reader.read(&mut data)?;
        Ok(FilterAdd { data })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        var_int::write(self.data.len() as u64, writer)?;
        writer.write(&self.data)?;
        Ok(())
    }
}

impl Payload<FilterAdd> for FilterAdd {
    fn size(&self) -> usize {
        var_int::size(self.data.len() as u64) + self.data.len()
    }
}

impl fmt::Debug for FilterAdd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("FilterAdd")
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}
