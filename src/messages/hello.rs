use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use crate::keys::public_to_slice;
use super::message::Payload;
use crate::connection::{MAX_PAYLOAD_SIZE, OriginatedEncryptedConnection, RLPX_TRANSPORT_PROTOCOL_VERSION};

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

        const HEADER_LEN: usize = 16;
		let mut header = RlpStream::new();
		let len = payload.len();
		if len > MAX_PAYLOAD_SIZE {
			panic!("OversizedPacket {}", len);
		}

		header.append_raw(&[(len >> 16) as u8, (len >> 8) as u8, len as u8], 1);
		header.append_raw(&[0xc2u8, 0x80u8, 0x80u8], 1);
		let padding = (16 - (len % 16)) % 16;

		let mut packet: Vec<u8> = vec![0u8; 16 + 16 + len + padding + 16];
		let mut header = header.out();
		header.resize(HEADER_LEN, 0u8);
		&mut packet[..HEADER_LEN].copy_from_slice(&mut header);
		self.connection.encoder.encrypt(&mut packet[..HEADER_LEN]).unwrap();
		OriginatedEncryptedConnection::update_mac(&mut self.connection.egress_mac, &self.connection.mac_encoder_key, &packet[..HEADER_LEN]);
		self.connection.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.connection.encoder.encrypt(&mut packet[32..32 + len]).unwrap();
		if padding != 0 {
			self.connection.encoder.encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}
		self.connection.egress_mac.update(&packet[32..(32 + len + padding)]);
		OriginatedEncryptedConnection::update_mac(&mut self.connection.egress_mac, &self.connection.mac_encoder_key, &[0u8; 0]);
		self.connection.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);

        
        // self.connection.write_packet(payload.as_ref());
        writer.write_all(packet.as_ref())
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