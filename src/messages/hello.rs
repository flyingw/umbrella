use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use crate::keys::public_to_slice;
use super::message::Payload;
use crate::connection::{MAX_PAYLOAD_SIZE, OriginatedEncryptedConnection, RLPX_TRANSPORT_PROTOCOL_VERSION};
//use ethkey::Secret; - this fucking import leads to SegFail

const PACKET_HELLO: u8 = 0x80; // actually 0x00 rlp doc "The integer 0 = [ 0x80 ]"
const CLIENT_NAME: &str = "umbrella";
const LOCAL_PORT: u16 = 1234;

pub struct Hello<'a> {
    pub connection: &'a mut OriginatedEncryptedConnection,
}

impl <'a> Serializable<Hello<'a>> for Hello<'a>{
    fn read(_reader: &mut dyn Read) -> Result<Hello<'a>> {
        panic!("can't read yet");
    }

    fn write(&mut self, writer: &mut dyn Write) -> io::Result<()> {
        println!("write hello");

        use rlp::RlpStream;
        use crate::hash128::Hash128;
        use parity_crypto::aes::AesEcb256;
        use super::message::ETH_63_CAPABILITY;

        let mut rlp = RlpStream::new();
        let u_public_key = &public_to_slice(&self.connection.public_key)[..];
        rlp.append_raw(&[PACKET_HELLO], 0)
            .begin_list(5)
            .append(&RLPX_TRANSPORT_PROTOCOL_VERSION)
            .append(&CLIENT_NAME)
            .append_list(&vec!(ETH_63_CAPABILITY))
            .append(&LOCAL_PORT)
            .append(&u_public_key);
        
        let payload: &[u8] = &rlp.out();
        let len = payload.len();
        if len > MAX_PAYLOAD_SIZE {
			panic!("OversizedPacket {}", len);
		}

        //
        const HEADER_LEN: usize = 16;
        let mut header = [0u8;HEADER_LEN];
        let (sz, rest) = header.split_at_mut(3);
        sz.copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        let (magic, _) = rest.split_at_mut(3);
        magic.copy_from_slice(&[0xc2u8, 0x80u8, 0x80u8]);
        
        self.connection.encoder.encrypt(&mut header).unwrap();

        writer.write_all(&header)?;

        let padding = (16 - (len % 16)) % 16;
        let mut packet: Vec<u8> = vec![0u8; 16 + 16 + len + padding + 16];

        // connection drops previous shit here
		let mut prev = Hash128::default();
        debug!("default bytes? 1{:?}", prev.as_bytes());

        self.connection.egress_mac.clone().finalize(prev.as_bytes_mut());
        debug!("default bytes? 2{:?}", prev.as_bytes());

        // we encrypt this previous shit
		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());

		let mac_encoder = AesEcb256::new(&self.connection.mac_encoder_key.as_bytes()).unwrap();
		mac_encoder.encrypt(enc.as_bytes_mut()).unwrap();

        // to previous mac we've add fucking xor of header
        // and update tha mac 
		enc = enc ^ Hash128::from_slice(&header);
		self.connection.egress_mac.update(enc.as_bytes());

        // write that shit next to packet header
		self.connection.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);

        // add fucking payload and encrypt it
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.connection.encoder.encrypt(&mut packet[32..32 + len]).unwrap();

        // padding + encrypted padding
		if padding != 0 {
			self.connection.encoder.encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}

        // header +
        writer.write_all(&packet[HEADER_LEN..32])?;
        
        // update mac with new fucking data
		self.connection.egress_mac.update(&packet[32..(32 + len + padding)]);
        writer.write_all(&packet[32..(32 + len + padding)])?;

        // something we've in mac
        let mut prev = Hash128::default();
        self.connection.egress_mac.clone().finalize(prev.as_bytes_mut());

        debug!("prev bytes {:?}", prev.as_bytes());

        // xor previous bytes with encrypted of this previous bytes
		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
        let mac_encoder = AesEcb256::new(&self.connection.mac_encoder_key.as_bytes()).unwrap();
		mac_encoder.encrypt(enc.as_bytes_mut()).unwrap();

        debug!("prev enc {:?}", enc.as_bytes());
        debug!("    prev {:?}", prev.as_bytes());
        debug!("     xor {:?}", (enc ^ prev).as_bytes());
		
        // egress mac update agani with xored encrypted shit
        self.connection.egress_mac.update((enc ^ prev).as_bytes());

        let mut b = [0;16];
        self.connection.egress_mac.clone().finalize(&mut b);

        debug!("last 16 {:?}", b);
        writer.write_all(&b)
    }

}

impl <'a> Payload<Hello<'a>> for Hello<'a> {
    fn size(&self) -> usize {
        0
    }
}

impl fmt::Debug for Hello<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hello")
            //.field("version", &self)
            .finish()
    }
}