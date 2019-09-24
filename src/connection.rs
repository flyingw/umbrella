use std::io::Write;
use crate::hash128::Hash128;
use rlp::RlpStream;
use secp256k1::key::{PublicKey, SecretKey};
use std::net::TcpStream;
use tiny_keccak::Keccak;
use aes::Aes256;
use block_modes::{BlockMode, Ecb, block_padding::ZeroPadding};
use aes_ctr::Aes256Ctr;
use aes_ctr::stream_cipher::SyncStreamCipher;

pub const RLPX_TRANSPORT_PROTOCOL_VERSION: u32 = 5;
pub const RLPX_TRANSPORT_AUTH_ACK_PACKET_SIZE_V4: usize = 210;
pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

pub const NULL_IV: [u8; 16] = [0;16];

pub struct OriginatedEncryptedConnection {
	pub stream: TcpStream,
	pub public_key: PublicKey,
	pub encoder: Aes256Ctr,
	pub decoder: Aes256Ctr,
	pub mac_encoder_key: SecretKey,
	pub egress_mac: Keccak,
	pub ingress_mac: Keccak,
    pub expected:[u8; 12],
}

use std::io;

impl OriginatedEncryptedConnection {
	pub fn write_packet(&mut self, payload: &[u8]) -> io::Result<()> {
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
		self.encoder.try_apply_keystream(&mut packet[..HEADER_LEN]).unwrap();
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &packet[..HEADER_LEN]);
		self.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.encoder.try_apply_keystream(&mut packet[32..32 + len]).unwrap();
		if padding != 0 {
			self.encoder.try_apply_keystream(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}
		self.egress_mac.update(&packet[32..(32 + len + padding)]);
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0]);
		self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);

		self.stream.write_all(packet.as_ref())
	}

  /// Update MAC after reading or writing any data.
	fn update_mac(mac: &mut Keccak, mac_encoder_key: &SecretKey, seed: &[u8]) -> () {
		let mut prev = Hash128::default();
		mac.clone().finalize(prev.as_bytes_mut());
		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
		
        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&mac_encoder_key[..], &[]).unwrap();
		let enc_mut = enc.as_bytes_mut();
		mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();

		enc = enc ^ if seed.is_empty() { prev } else { Hash128::from_slice(seed) };
		mac.update(enc.as_bytes());
	}
}
