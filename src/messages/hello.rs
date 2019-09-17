use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::result::Result;
use crate::serdes::Serializable;
use super::message::Payload;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Hello<'a> {
    pub payload: &'a Vec<u8>,
}

impl <'a> Serializable<Hello<'a>> for Hello<'a>{
    fn read(_reader: &mut dyn Read) -> Result<Hello<'a>> {
        panic!("can't read yet");
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        println!("write hello");
        use rlp::RlpStream;
        use crate::connection::{MAX_PAYLOAD_SIZE, OriginatedEncryptedConnection};

        const HEADER_LEN: usize = 16;
		let mut header = RlpStream::new();
		let len = self.payload.len();
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

		// self.encoder.encrypt(&mut packet[..HEADER_LEN]).unwrap();

		// OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &packet[..HEADER_LEN]);
		// self.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		// &mut packet[32..32 + len].copy_from_slice(self.payload);
		// self.encoder.encrypt(&mut packet[32..32 + len]).unwrap();
		// if padding != 0 {
		// 	self.encoder.encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		// }
		// self.egress_mac.update(&packet[32..(32 + len + padding)]);
		// OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0]);
		// self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);

		//self.stream.write_bytes(packet.as_ref());
        writer.write_all(self.payload.as_ref())
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