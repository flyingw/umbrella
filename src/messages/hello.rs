use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use crate::keys::public_to_slice;
use super::message::Payload;
use crate::connection::{MAX_PAYLOAD_SIZE, OriginatedEncryptedConnection, RLPX_TRANSPORT_PROTOCOL_VERSION};
use crate::ctx::Ctx;
use crate::hash128::Hash128;
use parity_crypto::aes::AesEcb256;
use super::message::ETH_63_CAPABILITY;
use secp256k1::key::PublicKey;
use ethkey::Secret;

//use ethkey::Secret; - this fucking import leads to SegFail

const PACKET_HELLO: u8 = 0x80; // actually 0x00 rlp doc "The integer 0 = [ 0x80 ]"
const CLIENT_NAME: &str = "umbrella";
const LOCAL_PORT: u16 = 1234;

pub struct Hello {
    //pub connection: &'a mut OriginatedEncryptedConnection,
    pub public_key: PublicKey,
    pub mac_encoder_key: Secret,
}

impl Serializable<Hello> for Hello{
    fn read(_reader: &mut dyn Read) -> Result<Hello> {
        panic!("can't read yet");
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        println!("write hello");
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

        const HEADER_LEN: usize = 16;
        let mut header = [0u8;HEADER_LEN];
        let (pl_sz, rest) = header.split_at_mut(3);
        let (magic, _) = rest.split_at_mut(3);
        pl_sz.copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        magic.copy_from_slice(&[0xc2u8, 0x80u8, 0x80u8]); // magic

        Ctx::encoder(ctx).encrypt(&mut header).unwrap();
        writer.write_all(&header)?;
    //->
        let padding = (16 - (len % 16)) % 16;
        let mut packet: Vec<u8> = vec![0u8; 16 + 16 + len + padding + 16];

		let mut prev = Hash128::default();
        debug!("default bytes? 1{:?}", prev.as_bytes());
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());
        debug!("default bytes? 2{:?}", prev.as_bytes());

		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());

		let mac_encoder = AesEcb256::new(&self.mac_encoder_key.as_bytes()).unwrap();
		mac_encoder.encrypt(enc.as_bytes_mut()).unwrap();

		enc = enc ^ Hash128::from_slice(&header);

        Ctx::update_remote_mac(ctx, enc.as_bytes());
        Ctx::get_remote_mac(ctx, &mut packet[HEADER_LEN..32]);

        // add fucking payload and encrypt it
		&mut packet[32..32 + len].copy_from_slice(&payload);
        Ctx::encoder(ctx).encrypt(&mut packet[32..32 + len]).unwrap();

		if padding != 0 {
            Ctx::encoder(ctx).encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}

        // header +
        writer.write_all(&packet[HEADER_LEN..32])?;
        
        Ctx::update_remote_mac(ctx, &packet[32..(32 + len + padding)]);

        writer.write_all(&packet[32..(32 + len + padding)])?;

        let mut prev = Hash128::default();
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());

        debug!("prev bytes {:?}", prev.as_bytes());

		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
        let mac_encoder = AesEcb256::new(&self.mac_encoder_key.as_bytes()).unwrap();
		mac_encoder.encrypt(enc.as_bytes_mut()).unwrap();

        debug!("prev enc {:?}", enc.as_bytes());
        debug!("    prev {:?}", prev.as_bytes());
        debug!("     xor {:?}", (enc ^ prev).as_bytes());
		
        Ctx::update_remote_mac(ctx, (enc ^ prev).as_bytes());

        let mut b = [0;16];
        Ctx::get_remote_mac(ctx, &mut b);
        debug!("last 16 {:?}", b);
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

#[cfg(test)]
mod tests {
    #[test]
    fn rlp_out(){
        use super::*;
        use rlp::RlpStream;
        // c0 = 0
        // c1 = 1
        // ca = 2
        // d1 = 3 
        // d4 = 4
        // d5 = 5
        // d6 = 6
        // d7 = 7
        // d8 = 8
        // d9 = 9
        // da = 10
        let mut key = vec![0u8;64];

        let mut rlp = RlpStream::new();
        rlp.append_raw(&[PACKET_HELLO], 0)
            .begin_list(5)
            .append(&RLPX_TRANSPORT_PROTOCOL_VERSION)
            .append(&CLIENT_NAME)
            .append_list(&vec!(ETH_63_CAPABILITY))
            .append(&LOCAL_PORT)
            .append(&key);
        let out = rlp.out();

        println!("out {:?}", &out);
        println!("out {:x?}", &out);
        let mut payload:Vec<u8> = vec![];
        payload.push(PACKET_HELLO);
        payload.push(0xf8); // f8 56 comes with long key
        payload.push(0x56); // instead of 0xd5 as 5 element in list
        payload.push( ((RLPX_TRANSPORT_PROTOCOL_VERSION)&0xff) as u8);
        payload.append(&mut vec![0x88, b'u',b'm',b'b',b'r',b'e',b'l',b'l',b'a']);
        payload.push(0xc6); // magic numbers c6 append list of 1 element
        payload.push(0xc5); // c5 below with list of 2 element
        payload.push(0x83); // lenght 3
        payload.append(&mut ETH_63_CAPABILITY.protocol.to_vec());
        payload.push(ETH_63_CAPABILITY.version);
        payload.push(0x82); // 2 bytes
        payload.push(((LOCAL_PORT >> 8) & 0xff) as u8);
        payload.push((LOCAL_PORT & 0xff) as u8);
        payload.push(0xb8); // list
        payload.push(0x40); // 64 elements
        payload.append(&mut key);

        //let cmp = vec![0x80, 
        //    0xd5, 
        //        0xf8, 0x56, was 0xd5
        //        0x88, 0x75, 0x6d, 0x62, 0x72, 0x65, 0x6c, 0x6c, 0x61, 
        //        0xc6, 
        //          0xc5, 
        //              0x83, 0x65, 0x74, 0x68, 
        //              0x3f, 
        //        0x82,
        //            0x4, 0xd2, 
        //        0xb8, 
        //            0x40, 0....];
        
        assert_eq!(out, payload);
    } 
}