use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::keys::public_to_slice;
use super::message::Payload;
use crate::ctx::Ctx;
use crate::hash128::Hash128;
use super::message::ETH_63_CAPABILITY;
use secp256k1::key::{PublicKey};
use aes::Aes256;
use block_modes::{BlockMode, Ecb, block_padding::{ZeroPadding}};
use aes_ctr::stream_cipher::SyncStreamCipher;
use crate::keys::{slice_to_public};

const PACKET_HELLO: u8 = 0x80; // actually 0x00 rlp doc "The integer 0 = [ 0x80 ]"
const CLIENT_NAME: &str = "umbrella";
const LOCAL_PORT: u16 = 1234;

const RLPX_TRANSPORT_PROTOCOL_VERSION: u32 = 5;
const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

#[derive(Clone)]
pub struct Hello {
    pub public_key: PublicKey,
}

impl Serializable<Hello> for Hello{
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Hello> {
        let mut packet_id_buf: Vec<u8> = vec![0u8; 1];
        reader.read_exact(packet_id_buf.as_mut())?;
        let packet_id: u8 = packet_id_buf[0];
        if packet_id == PACKET_HELLO {
            let mut payload = Vec::new();
            reader.read_to_end(&mut payload)?;
            let public_key = slice_to_public(&payload[payload.len() - 64..])?;
            Ok(Hello{
                public_key: public_key,
            })
        } else {
            Err(Error::ScriptError(format!("not a Hello message, id={}", packet_id)))
        }
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        let u_public_key = &public_to_slice(&self.public_key)[..];
        
        // check some comments in module tests below
        let mut payload:Vec<u8> = vec![];
        payload.push(PACKET_HELLO);
        payload.push(0xf8);
        payload.push(0x56);
        payload.push( ((RLPX_TRANSPORT_PROTOCOL_VERSION)&0xff) as u8);
        payload.append(&mut vec![0x88, b'u',b'm',b'b',b'r',b'e',b'l',b'l',b'a']);
        payload.push(0xc6);
        payload.push(0xc5);
        payload.push(0x83);
        payload.append(&mut ETH_63_CAPABILITY.protocol.to_vec());
        payload.push(ETH_63_CAPABILITY.version);
        payload.push(0x82);
        payload.push(((LOCAL_PORT >> 8) & 0xff) as u8);
        payload.push((LOCAL_PORT & 0xff) as u8);
        payload.push(0xb8);
        payload.push(0x40);
        payload.append(&mut u_public_key.to_vec());

        let len = payload.len();
        if len > MAX_PAYLOAD_SIZE {
			panic!("OversizedPacket {}", len);
		}

        let padding = (16 - (len % 16)) % 16;
        let mut packet: Vec<u8> = vec![0u8; len + padding + 16];
        
		&mut packet[..len].copy_from_slice(&payload);
        Ctx::encoder(ctx).try_apply_keystream(&mut packet[..len]).unwrap();

		if padding != 0 {
            Ctx::encoder(ctx).try_apply_keystream(&mut packet[len..(len + padding)]).unwrap();
		}

        Ctx::update_remote_mac(ctx, &packet[..(len + padding)]);

        writer.write_all(&packet[..(len + padding)])?;

        let mut prev = Hash128::default();
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());

		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());

        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).expect("failed to aes ecb 1");
	    let enc_mut = enc.as_bytes_mut();
		mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();

        Ctx::update_remote_mac(ctx, (enc ^ prev).as_bytes());

        let mut b = [0;16];
        Ctx::get_remote_mac(ctx, &mut b);
        writer.write_all(&b)
    }

}

impl Payload<Hello> for Hello {
    fn size(&self) -> usize {
        78 + CLIENT_NAME.len() + ETH_63_CAPABILITY.protocol.len()
    }
}

impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hello")
            //.field("version", &self)
            .finish()
    }
}
