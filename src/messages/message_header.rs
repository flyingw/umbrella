use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::str;
use crate::result::{Error, Result};
use crate::ctx::Ctx;
use crate::serdes::Serializable;
use aes_ctr::stream_cipher::SyncStreamCipher;
use crate::hash128::Hash128;
use block_modes::{BlockMode, Ecb, block_padding::{ZeroPadding}};
use aes::Aes256;

pub trait MsgHeader: Send + Sync {
    fn command(&self) -> [u8;12];
    fn payload(&self, reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<Vec<u8>>;
    fn payload_size(&self) -> u32;
}

impl MsgHeader for MessageHeader {
    fn command(&self) -> [u8;12] { self.command }
    fn payload_size(&self) -> u32 {self.payload_size }
    fn payload(&self, reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Vec<u8>> { self.payload(reader) }    
}

impl MsgHeader for SecHeader {
    fn command(&self) -> [u8;12] { self.command }
    fn payload_size(&self) -> u32 {self.payload_size }
    fn payload(&self, reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<Vec<u8>> { self.payload(reader, ctx) }    
}

/// Header that begins all messages
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MessageHeader {
    /// Magic bytes indicating the network type
    pub magic: [u8; 4],
    /// Command name
    pub command: [u8; 12],
    /// Payload size
    pub payload_size: u32,
    /// First 4 bytes of SHA256(SHA256(payload))
    pub checksum: [u8; 4],
}

/// Encrypted header for all messages with encryption
#[derive(Clone)]
pub struct SecHeader {
    /// Magic bytes indicating the network type
    pub magic: [u8; 3],
    /// Command name
    pub command: [u8; 12],
    /// Payload size
    pub payload_size: u32,
}
    /// Secret key, x in ECDSA signature
    // pub secret: SecretKey,

impl MessageHeader {
    /// Size of the message header in bytes
    pub const SIZE: usize = 24;

    /// Returns the size of the header in bytes
    pub fn size(&self) -> usize {
        MessageHeader::SIZE
    }

    /// Checks if the header is valid
    ///
    /// `magic` - Expected magic bytes for the network
    /// `max_size` - Max size in bytes for the payload
    pub fn validate(&self, magic: [u8; 4], max_size: u32) -> Result<()> {
        if self.magic != magic {
            let msg = format!("Bad magic: {:?}", self.magic);
            return Err(Error::BadData(msg));
        }
        if self.payload_size > max_size {
            let msg = format!("Bad size: {:?}", self.payload_size);
            return Err(Error::BadData(msg));
        }
        Ok(())
    }

    /// Reads the payload and verifies its checksum
    pub fn payload(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut p = vec![0; self.payload_size as usize];
        reader.read_exact(p.as_mut())?;
        let hash = digest::digest(&digest::SHA256, p.as_ref());
        let hash = digest::digest(&digest::SHA256, &hash.as_ref());
        let h = &hash.as_ref();
        let j = &self.checksum;
        if h[0] != j[0] || h[1] != j[1] || h[2] != j[2] || h[3] != j[3] {
            let msg = format!("Bad checksum: {:?} != {:?}", &h[..4], j);
            return Err(Error::BadData(msg));
        }
        Ok(p)
    }
}

impl SecHeader {
    pub const HEADER_LEN: usize = 16;
    pub const ENCRYPTED_HEADER_LEN: usize = 32;

    /// Reads the payload and verifies its checksum
    pub fn payload(&self, reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<Vec<u8>> {
        let payload_size = self.payload_size as usize;
        let padding = (16 - (payload_size % 16)) % 16;
        let full_length = payload_size + padding + 16;

        let mut payload: Vec<u8> = vec![0u8; full_length];
        reader.read_exact(payload.as_mut_slice())?;

        ctx.update_local_mac(&payload[0..payload.len() - SecHeader::HEADER_LEN]);
        let mut prev = Hash128::default();
        ctx.get_local_mac(prev.as_bytes_mut());
        let mut enc = Hash128::default();
        &mut enc[..].copy_from_slice(prev.as_bytes());
        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).unwrap();
        let enc_mut = enc.as_bytes_mut();
        mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();
        enc = enc ^ prev;
        ctx.update_local_mac(enc.as_bytes());
	    let mac = &payload[(payload.len() - SecHeader::HEADER_LEN)..];
        let mut expect = Hash128::default();
        ctx.get_local_mac(expect.as_bytes_mut());
		if mac != expect.as_bytes() { panic!("paylaod auth error. mac is not valid"); }
		
		ctx.decoder().try_apply_keystream(&mut payload[..payload_size + padding]).unwrap();
		payload.truncate(payload_size);
        return Ok(payload);
    }
}

impl Serializable<MessageHeader> for MessageHeader {
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<MessageHeader> {
        // Read all the bytes at once so that the stream doesn't get in a partially-read state
        let mut p = vec![0; MessageHeader::SIZE];
        reader.read_exact(p.as_mut())?;
        let mut c = Cursor::new(p);

        // Now parse the results from the stream
        let mut ret = MessageHeader {
            ..Default::default()
        };
        c.read(&mut ret.magic)?;
        c.read(&mut ret.command)?;
        ret.payload_size = c.read_u32::<LittleEndian>()?;
        c.read(&mut ret.checksum)?;

        Ok(ret)
    }

    fn write(&self, writer: &mut dyn Write, _ctx: &mut dyn Ctx) -> io::Result<()> {
        writer.write(&self.magic)?;
        writer.write(&self.command)?;
        writer.write_u32::<LittleEndian>(self.payload_size)?;
        writer.write(&self.checksum)?;
        Ok(())
    }
}

impl Serializable<SecHeader> for SecHeader {
    fn read(reader: &mut dyn Read, ctx: &mut dyn Ctx) -> Result<SecHeader> {
        let mut header: Vec<u8> = vec![0u8; SecHeader::ENCRYPTED_HEADER_LEN];
        reader.read_exact(header.as_mut_slice())?;

        let mut prev = Hash128::default();
        ctx.get_local_mac(prev.as_bytes_mut());
        let mut enc = Hash128::default();
        &mut enc[..].copy_from_slice(prev.as_bytes());
        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).unwrap();
        let enc_mut = enc.as_bytes_mut();
        mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();
        enc = enc ^ Hash128::from_slice(&header[..SecHeader::HEADER_LEN]);
        ctx.update_local_mac(enc.as_bytes());
        let mac = &header[SecHeader::HEADER_LEN..];
        let mut expect = Hash128::default();
        ctx.get_local_mac(expect.as_bytes_mut());
        if mac != expect.as_bytes() { panic!("header auth error. mac is not valid"); }

        ctx.decoder().try_apply_keystream(&mut header[..SecHeader::HEADER_LEN]).expect("failed aes ctr 1");
        let length = ((((header[0] as u32) << 8) + (header[1] as u32)) << 8) + (header[2] as u32);

        Ok(SecHeader {
            magic: Default::default(),
            command: Default::default(),
            payload_size: length,
        })
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        debug!("=>write short header");
        
        use std::convert::TryInto;
        let len: usize = self.payload_size.try_into().unwrap();
        let mut header = [0u8; SecHeader::HEADER_LEN];
        let (pl_sz, rest) = header.split_at_mut(3);
        let (magic, _) = rest.split_at_mut(3);
        pl_sz.copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        magic.copy_from_slice(&self.magic);

        Ctx::encoder(ctx).try_apply_keystream(&mut header).unwrap();
        writer.write_all(&header)?;

		let mut prev = Hash128::default();
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());
        
		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());

        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).expect("failed to aes ecb 1");
	    let enc_mut = enc.as_bytes_mut();
		mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();

		enc = enc ^ Hash128::from_slice(&header);
        Ctx::update_remote_mac(ctx, enc.as_bytes());

        let mut mac = [0;16];
        Ctx::get_remote_mac(ctx, &mut mac);
        writer.write_all(&mac)
    }
}

// Prints so the command is easier to read
impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = match str::from_utf8(&self.command) {
            Ok(s) => s.to_string(),
            Err(_) => format!("Not Ascii ({:?})", self.command),
        };
        write!(
            f,
            "Header {{ magic: {:?}, command: {:?}, payload_size: {}, checksum: {:?} }}",
            self.magic, command, self.payload_size, self.checksum
        )
    }
}

impl fmt::Debug for SecHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let command = match str::from_utf8(&self.command) {
            Ok(s) => s.to_string(),
            Err(_) => format!("Not Ascii ({:?})", self.command),
        };
        write!(
            f,
            "Header {{ magic: {:?}, command: {:?}, payload_size: {},}}",
            self.magic, command, self.payload_size
        )
    }
}
