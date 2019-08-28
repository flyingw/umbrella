extern crate ethkey;
extern crate ethereum_types;
extern crate keccak_hash;
extern crate parity_crypto;
extern crate tiny_keccak;
extern crate secp256k1;
extern crate rand;
extern crate rlp;

use std::io::{Write, Read};
use std::str::FromStr;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use keccak_hash::{keccak, write_keccak};
use tiny_keccak::Keccak;
use ethereum_types::{H128, H256, H512};
use ethkey::{Generator, Random, sign, Secret, Public, KeyPair};
use ethkey::crypto::{ecdh, ecies, Error};
use parity_crypto::aes::{AesCtr256, AesEcb256};
use rlp::{RlpStream, Encodable};

use std::{thread, time};

const V4_ACK_PACKET_SIZE: usize = 210;
const NULL_IV : [u8; 16] = [0;16];
const PACKET_HELLO: u8 = 0x80;
const PROTOCOL_VERSION: u32 = 5;
pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

fn main() {
	let enode: &str = "enode://16cabdd5c1049a54255a52ed775ee5ed1b4f3fd52bf25b751470a59bda8f093df563dc5d385103e46314ff5dacb8f37fcd988b20efc63b9b5fa78f5417971b48@127.0.0.1:30301";
	let node: RemoteNode = RemoteNode::parse(enode).unwrap();
	let connection: OriginatedConnection = OriginatedConnection::connect(node);
	let mut connection: OriginatedEncryptedConnection = OriginatedEncryptedConnection::create(connection);
	connection.say_hello();
}

pub struct RemoteNode {
	key: Public,
	address: SocketAddr,
}

impl RemoteNode {
	fn parse(enode: &str) -> Result<RemoteNode, String> {
		if enode.len() > 136 && &enode[0..8] == "enode://" && &enode[136..137] == "@" {
			let key: Public = enode[8..136].parse().map_err(|err| format!("network: failed to parse enode pub_key err={:?}", err))?;
			let address_str: &str = &enode[137..];
			match address_str.to_socket_addrs().map(|mut i| i.next()) {
				Ok(Some(address)) => 
					return Ok(RemoteNode {
						key: key,
						address: address,
					}),
				Ok(None) => return Err(format!("network: unable to resolve enode address {}", address_str)),
				Err(err) => return Err(format!("network: failed to parse enode address={}, with err={:?}", address_str, err))
			}
		} else {
			return Err(format!("network: wrong enode={}, expect 'enode://pub_key@ip:port'", enode));
		}
	}
}

pub struct OriginatedConnection {
	stream: TcpStream,
	local_keys: KeyPair,
	nonce: H256,
	remote_nonce: H256,
	ecdhe: KeyPair,
	auth_cipher: Vec<u8>,
	ack_cipher: Vec<u8>,
	remote_ephemeral: Public,
}

impl OriginatedConnection {
	fn connect(node: RemoteNode) -> OriginatedConnection {
		let nonce: H256 = H256::random();

		let keys: KeyPair = Random.generate().unwrap();

		//handshake write
		let ecdhe: KeyPair = Random.generate().unwrap();
		let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1]; //TODO: use associated constants
		let data_len = data.len();
		
		data[data_len - 1] = 0x0;
		let (sig, rest) = data.split_at_mut(65);
		let (hepubk, rest) = rest.split_at_mut(32);
		let (pubk, rest) = rest.split_at_mut(64);
		let (dataNonce, _) = rest.split_at_mut(32);

		// E(remote-pubk, S(ecdhe-random, ecdh-shared-secret^nonce) || H(ecdhe-random-pubk) || pubk || nonce || 0x0)
		let shared: H256 = *ecdh::agree(keys.secret(), &node.key).unwrap();
		sig.copy_from_slice(&*sign(ecdhe.secret(), &(shared ^ nonce)).unwrap());
		write_keccak(ecdhe.public(), hepubk);
		pubk.copy_from_slice(keys.public().as_bytes());
		dataNonce.copy_from_slice(nonce.as_bytes());
		
		let message: Vec<u8> = ecies::encrypt(&node.key, &[], &data).unwrap();
		let auth_cipher: Vec<u8> = message.clone();
		
		let mut stream: TcpStream = TcpStream::connect(node.address).unwrap();
		stream.write(message.as_ref()).unwrap();
		
		//handshake read
		let mut data: [u8; V4_ACK_PACKET_SIZE] = [0u8; V4_ACK_PACKET_SIZE];
		let data_len: usize = stream.read(&mut data).unwrap();
		if data_len != V4_ACK_PACKET_SIZE {
			panic!("network: wrong ack packaet size. expect={}, actual={}", V4_ACK_PACKET_SIZE, data_len);
		}
		let ack_cipher: Vec<u8> = data.clone().to_vec();
		let connection: OriginatedConnection = ecies::decrypt(keys.secret(), &[], &data).map(|ack| {
			let mut remote_ephemeral: Public = Public::default();
			let mut remote_nonce: H256 = H256::zero();

			remote_ephemeral.assign_from_slice(&ack[0..64]);
			remote_nonce.assign_from_slice(&ack[64..(64+32)]);		
			println!("network: read ack ok");
			OriginatedConnection {
				stream: stream,
				local_keys: keys,
				nonce: nonce,
				remote_nonce: remote_nonce,
				ecdhe: ecdhe,
				auth_cipher: auth_cipher,
				ack_cipher: ack_cipher,
				remote_ephemeral: remote_ephemeral,
			}
		}).unwrap();
		return connection;
	}
}

pub struct OriginatedEncryptedConnection {
	stream: TcpStream,
	local_keys: KeyPair,
	encoder: AesCtr256,
	decoder: AesCtr256,
	mac_encoder_key: Secret,
	egress_mac: Keccak,
	ingress_mac: Keccak,
}

impl OriginatedEncryptedConnection {
	fn create(connection: OriginatedConnection) -> OriginatedEncryptedConnection {
		let shared = ecdh::agree(connection.ecdhe.secret(), &connection.remote_ephemeral).unwrap();
		let mut nonce_material = H512::default();
		(&mut nonce_material[0..32]).copy_from_slice(connection.remote_nonce.as_bytes());
		(&mut nonce_material[32..64]).copy_from_slice(connection.nonce.as_bytes());
		let mut key_material = H512::default();
		(&mut key_material[0..32]).copy_from_slice(shared.as_bytes());
		write_keccak(&nonce_material, &mut key_material[32..64]);
		let key_material_keccak = keccak(&key_material);
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
		let key_material_keccak = keccak(&key_material);
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());

		// Using a 0 IV with CTR is fine as long as the same IV is never reused with the same key.
		// This is the case here: ecdh creates a new secret which will be the symmetric key used
		// only for this session the 0 IV is only use once with this secret, so we are in the case
		// of same IV use for different key.
		let encoder = AesCtr256::new(&key_material[32..64], &NULL_IV).unwrap();
		let decoder = AesCtr256::new(&key_material[32..64], &NULL_IV).unwrap();
		let key_material_keccak = keccak(&key_material);
		(&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
		let mac_encoder_key: Secret = Secret::from_slice(&key_material[32..64]).unwrap();

		let mut egress_mac = Keccak::new_keccak256();
		let mut mac_material = H256::from_slice(&key_material[32..64]) ^ connection.remote_nonce;
		egress_mac.update(mac_material.as_bytes());
		egress_mac.update(&connection.auth_cipher);

		let mut ingress_mac = Keccak::new_keccak256();
		mac_material = H256::from_slice(&key_material[32..64]) ^ connection.nonce;
		ingress_mac.update(mac_material.as_bytes());
		ingress_mac.update(&connection.ack_cipher);

		return OriginatedEncryptedConnection {
			stream: connection.stream,
			encoder: encoder,
			decoder: decoder,
			mac_encoder_key: mac_encoder_key,
			egress_mac: egress_mac,
			ingress_mac: ingress_mac,
			local_keys: connection.local_keys,
		};
	}

	fn say_hello(&mut self) -> () {
		let fake_port: u16 = 1234;
		let mut rlp = RlpStream::new();
		rlp.append_raw(&[PACKET_HELLO as u8], 0);
		rlp.begin_list(5)
			.append(&PROTOCOL_VERSION)
			.append(&"simple-client")
			.append_list(&vec!(ETH_63))
			.append(&fake_port)
			.append(self.local_keys.public());
		self.send_packet(&rlp.drain());
	}

	pub fn send_packet(&mut self, payload: &[u8]) -> () {
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
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &packet[..HEADER_LEN]).unwrap();
		self.egress_mac.clone().finalize(&mut packet[HEADER_LEN..32]);
		&mut packet[32..32 + len].copy_from_slice(payload);
		self.encoder.encrypt(&mut packet[32..32 + len]).unwrap();
		if padding != 0 {
			self.encoder.encrypt(&mut packet[(32 + len)..(32 + len + padding)]).unwrap();
		}
		self.egress_mac.update(&packet[32..(32 + len + padding)]);
		OriginatedEncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0]).unwrap();
		self.egress_mac.clone().finalize(&mut packet[(32 + len + padding)..]);


		// self.connection.send(io, packet);

		self.stream.write(packet.as_ref()).unwrap();

		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
		let mut data: [u8;1000] = [0u8;1000];
		let data_len = self.stream.read(&mut data).unwrap();
		println!("data_len={}", data_len);
	}

	/// Update MAC after reading or writing any data.
	fn update_mac(mac: &mut Keccak, mac_encoder_key: &Secret, seed: &[u8]) -> Result<(), Error> {
		let mut prev = H128::default();
		mac.clone().finalize(prev.as_bytes_mut());
		let mut enc = H128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());
		let mac_encoder = AesEcb256::new(mac_encoder_key.as_bytes())?;
		mac_encoder.encrypt(enc.as_bytes_mut())?;

		enc = enc ^ if seed.is_empty() { prev } else { H128::from_slice(seed) };
		mac.update(enc.as_bytes());
		Ok(())
	}
}

pub type ProtocolId = [u8; 3];
pub struct CapabilityInfo {
	pub protocol: ProtocolId,
	pub version: u8,
	pub packet_count: u8,
}

impl Encodable for CapabilityInfo {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);
		s.append(&&self.protocol[..]);
		s.append(&self.version);
	}
}

pub const ETH_PROTOCOL: ProtocolId = *b"eth";
pub const ETH_PROTOCOL_VERSION_63: (u8, u8) = (63, 0x11);
pub const ETH_63: CapabilityInfo = CapabilityInfo { protocol: ETH_PROTOCOL, version: ETH_PROTOCOL_VERSION_63.0, packet_count: ETH_PROTOCOL_VERSION_63.1 };
