use std::io::{Write, Read};
use crate::hash128::{Hash128};
use crate::hash256::{Hash256};
use crate::hash512::{Hash512};
use ethereum_types::{H256};
use ethkey::{Secret, Public};
use ethkey::crypto::{ecdh};
use parity_crypto::aes::{AesCtr256, AesEcb256};
use rlp::{RlpStream, Rlp};
use secp256k1::key::{SecretKey, PublicKey};
use std::net::TcpStream;
use tiny_keccak::Keccak;

pub const RLPX_TRANSPORT_PROTOCOL_VERSION: u32 = 5;
pub const RLPX_TRANSPORT_AUTH_ACK_PACKET_SIZE_V4: usize = 210;
pub const ENCRYPTED_HEADER_LEN: usize = 32;
pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

const NULL_IV: [u8; 16] = [0;16];

pub struct OriginatedEncryptedConnection {
	stream: TcpReader,
	pub public_key: PublicKey,
	encoder: AesCtr256,
	decoder: AesCtr256,
	mac_encoder_key: Secret,
	egress_mac: Keccak,
	ingress_mac: Keccak,
}

impl OriginatedEncryptedConnection {
	pub fn new(stream: TcpReader,
        public_key: PublicKey,
        nonce: Hash256,
        remote_nonce: Hash256,
        ecdhe_secret_key: SecretKey,
        auth_cipher: Vec<u8>,
        ack_cipher: Vec<u8>,
        remote_ephemeral: Public) -> OriginatedEncryptedConnection {
		let ecdhe_secret = Secret::from_slice(&ecdhe_secret_key[0..32]).unwrap();
		let shared = ecdh::agree(&ecdhe_secret, &remote_ephemeral).unwrap();
		let mut nonce_material = Hash512::default();
		(&mut nonce_material[0..32]).copy_from_slice(remote_nonce.as_bytes());
		(&mut nonce_material[32..64]).copy_from_slice(nonce.as_bytes());
		let mut key_material = Hash512::default();
		(&mut key_material[0..32]).copy_from_slice(shared.as_bytes());
		Keccak::keccak256(nonce_material.as_bytes_mut(), &mut key_material[32..64]);
		let key_material_keccak = OriginatedEncryptedConnection::keccak(key_material.as_bytes());
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
		let key_material_keccak = OriginatedEncryptedConnection::keccak(key_material.as_bytes());
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());

		// Using a 0 IV with CTR is fine as long as the same IV is never reused with the same key.
		// This is the case here: ecdh creates a new secret which will be the symmetric key used
		// only for this session the 0 IV is only use once with this secret, so we are in the case
		// of same IV use for different key.
		let encoder = AesCtr256::new(&key_material[32..64], &NULL_IV).unwrap();
		let decoder = AesCtr256::new(&key_material[32..64], &NULL_IV).unwrap();
		let key_material_keccak = OriginatedEncryptedConnection::keccak(key_material.as_bytes());
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
		let mac_encoder_key: Secret = Secret::from_slice(&key_material[32..64]).unwrap();

		let mut egress_mac = Keccak::new_keccak256();
		let mut mac_material = Hash256::from_slice(&key_material[32..64]) ^ remote_nonce;
		egress_mac.update(mac_material.as_bytes());
		egress_mac.update(&auth_cipher);

		let mut ingress_mac = Keccak::new_keccak256();
		mac_material = Hash256::from_slice(&key_material[32..64]) ^ nonce;
		ingress_mac.update(mac_material.as_bytes());
		ingress_mac.update(&ack_cipher);

		return OriginatedEncryptedConnection {
			stream: stream,
			encoder: encoder,
			decoder: decoder,
			mac_encoder_key: mac_encoder_key,
			egress_mac: egress_mac,
			ingress_mac: ingress_mac,
			public_key: public_key,
		};
	}

	fn keccak(x: &[u8]) -> Hash256 {
		let mut res = Hash256::default();
		Keccak::keccak256(x, res.as_bytes_mut());
		res
	}

	pub fn write_packet(&mut self, payload: &[u8]) -> () {
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
		self.encoder.encrypt(&mut packet[..HEADER_LEN]).unwrap();
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &packet[..HEADER_LEN]);
		self.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.encoder.encrypt(&mut packet[32..32 + len]).unwrap();
		if padding != 0 {
			self.encoder.encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}
		self.egress_mac.update(&packet[32..(32 + len + padding)]);
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0]);
		self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);

		self.stream.write_bytes(packet.as_ref());
	}

	pub fn read_packet(&mut self) -> Option<Vec<u8>> {
		return self.read_header().and_then(|header| self.read_payload(header));
	}
	
	fn read_header(&mut self) -> Option<PacketHeader> {
		return self.stream.read_bytes(ENCRYPTED_HEADER_LEN).map(|data| self.parse_header(&data));
	}
	
	fn read_payload(&mut self, packet_header: PacketHeader) -> Option<Vec<u8>> {
		return self.stream.read_bytes(packet_header.full_length).map(|data| self.parse_payload(packet_header, &data));
	}

	fn parse_header(&mut self, data: &Vec<u8>) -> PacketHeader {
		if data.len() != ENCRYPTED_HEADER_LEN { panic!("wrong header len={}, expect={}", data.len(), ENCRYPTED_HEADER_LEN); }
		let mut header: Vec<u8> = data.to_owned();
		OriginatedEncryptedConnection::update_mac(&mut self.ingress_mac, &self.mac_encoder_key, &header[0..16]);

		let mac = &header[16..];
		let mut expected = H256::default();
		self.ingress_mac.clone().finalize(expected.as_bytes_mut());
		if mac != &expected[0..16] {
			panic!("auth error. mac is not valid");
		}
		self.decoder.decrypt(&mut header[..16]).unwrap();

		let length = ((((header[0] as u32) << 8) + (header[1] as u32)) << 8) + (header[2] as u32);
		let header_rlp = Rlp::new(&header[3..6]);
		let protocol_id = header_rlp.val_at::<u16>(0).unwrap();

		let padding = (16 - (length % 16)) % 16;
		let full_length = length + padding + 16;

		return PacketHeader {
 			protocol_id: protocol_id as usize,
 			payload_len: length as usize,
			full_length: full_length as usize,
		}
	}

	fn parse_payload(&mut self, packet_header: PacketHeader, data: &Vec<u8>) -> Vec<u8> {
		if data.len() != packet_header.full_length { panic!("wrong payload len={}, expect={}", data.len(), packet_header.full_length); }
		let mut payload: Vec<u8> = data.to_owned();
		self.ingress_mac.update(&payload[0..payload.len() - 16]);
		OriginatedEncryptedConnection::update_mac(&mut self.ingress_mac, &self.mac_encoder_key, &[0u8; 0]);

		let mac = &payload[(payload.len() - 16)..];
		let mut expected = Hash128::default();
		self.ingress_mac.clone().finalize(expected.as_bytes_mut());
		if mac != &expected[..] {
			panic!("auth error. mac is not valid");
		}
		let padding = (16 - (packet_header.payload_len % 16)) % 16;
		self.decoder.decrypt(&mut payload[..packet_header.payload_len + padding]).unwrap();
		payload.truncate(packet_header.payload_len);
    return payload;
	}

  /// Update MAC after reading or writing any data.
	fn update_mac(mac: &mut Keccak, mac_encoder_key: &Secret, seed: &[u8]) -> () {
		let mut prev = Hash128::default();
		mac.clone().finalize(prev.as_bytes_mut());
		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
		let mac_encoder = AesEcb256::new(mac_encoder_key.as_bytes()).unwrap();
		mac_encoder.encrypt(enc.as_bytes_mut()).unwrap();

		enc = enc ^ if seed.is_empty() { prev } else { Hash128::from_slice(seed) };
		mac.update(enc.as_bytes());
	}
}

pub struct PacketHeader {
	pub protocol_id: usize,
	pub payload_len: usize,
	pub full_length: usize,
}

pub struct TcpReader(pub TcpStream);

impl TcpReader {
	pub fn read_bytes(&mut self, bytes_to_read: usize) -> Option<Vec<u8>> {
		let mut buf: Vec<u8> = vec![0u8; bytes_to_read];
		let buf_len: usize = self.0.read(buf.as_mut_slice()).unwrap();
		if buf_len == 0 {
			return None;
		} else if buf_len == bytes_to_read {
			return Some(buf);
		} else {
			println!("read wrong len={}, expect={}", buf_len, bytes_to_read);
			return None;
		}
	}

	pub fn write_bytes(&mut self, buf: &[u8]) -> () {
		self.0.write(buf).unwrap();
	}
}
