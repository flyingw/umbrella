extern crate ethcore_network_devp2p;
extern crate ethkey;
extern crate ethereum_types;
extern crate keccak_hash;
extern crate parity_crypto;
extern crate tiny_keccak;

use std::io::{Write, Read};
use std::str::FromStr;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use ethcore_network_devp2p::node_table::{Node};
use keccak_hash::{keccak, write_keccak};
use tiny_keccak::Keccak;
use ethereum_types::{H256, H512};
use ethkey::{Generator, KeyPair, Random, Secret, Public, sign};
use ethkey::crypto::{ecdh, ecies, Error};
use parity_crypto::aes::{AesCtr256, AesEcb256};

const V4_ACK_PACKET_SIZE: usize = 210;
const NULL_IV : [u8; 16] = [0;16];

pub struct LocalData {
	
}



fn main() {
	let enode: &str = "enode://16cabdd5c1049a54255a52ed775ee5ed1b4f3fd52bf25b751470a59bda8f093df563dc5d385103e46314ff5dacb8f37fcd988b20efc63b9b5fa78f5417971b48@127.0.0.1:30301";
	let node: RemoteNode = parseEnode(enode).unwrap();
	// let node: Node = FromStr::from_str(enode).unwrap();

	let nonce: H256 = H256::random();

	let token: usize = 1; //for mio

	let keys: KeyPair = Random.generate().unwrap();
	println!("key={:?}", keys);

	//handshake write
	let ecdhe: KeyPair = Random.generate().unwrap();
	let mut data = [0u8; /*Signature::SIZE*/ 65 + /*H256::SIZE*/ 32 + /*Public::SIZE*/ 64 + /*H256::SIZE*/ 32 + 1]; //TODO: use associated constants
	let len = data.len();
	
	data[len - 1] = 0x0;
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
	// self.auth_cipher = message.clone();
	// self.connection.send(io, message);
	// self.connection.expect(V4_ACK_PACKET_SIZE);
	// self.state = HandshakeState::ReadingAck;
	
	let mut stream = TcpStream::connect(node.address).unwrap();
	stream.write(message.as_ref()).unwrap();
  
	//handshake read
	let mut data = [0u8; V4_ACK_PACKET_SIZE
	];
	let data_len = stream.read(&mut data).unwrap();

	if data_len != V4_ACK_PACKET_SIZE {
		println!("network: wrong ack packaet size. expect={}, actual={}", V4_ACK_PACKET_SIZE, data_len);
		return;
	}

	let mut remote_ephemeral: Public = Public::default();
	let mut remote_nonce: H256 = H256::zero();
	match ecies::decrypt(keys.secret(), &[], &data) {
		Ok(ack) => {
			remote_ephemeral.assign_from_slice(&ack[0..64]);
			remote_nonce.assign_from_slice(&ack[64..(64+32)]);		
			println!("network: read ack ok");
		}
		Err(_) => {
			// Try to interpret as EIP-8 packet
			// not implemented
			println!("network: EIP-8 packet not implemented");
			return;
		}
	}
}

pub struct RemoteNode {
	key: Public,
	address: SocketAddr,
}

fn parseEnode(enode: &str) -> Result<RemoteNode, String> {
	if enode.len() > 136 && &enode[0..8] == "enode://" && &enode[136..137] == "@" {
		let key: H512 = enode[8..136].parse().map_err(|err| format!("network: failed to parse enode pub_key err={:?}", err))?;
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

pub struct OriginatedHandshake {
	nonce: H256,
	remote_nonce: H256,
	ecdhe: KeyPair,
	auth_cipher: Vec<u8>,
	ack_cipher: Vec<u8>,
	remote_ephemeral: Public,
}

pub struct OriginatedEncryptedConnection {
	stream: TcpStream,
	encoder: AesCtr256,
	decoder: AesCtr256,
	mac_encoder_key: Secret,
	egress_mac: Keccak,
	ingress_mac: Keccak,
}

fn originatedEncriptedConnection(stream: TcpStream, Handshake: OriginatedHandshake) -> OriginatedEncryptedConnection {
	let shared = ecdh::agree(Handshake.ecdhe.secret(), &Handshake.remote_ephemeral).unwrap();
		let mut nonce_material = H512::default();
		(&mut nonce_material[0..32]).copy_from_slice(Handshake.remote_nonce.as_bytes());
		(&mut nonce_material[32..64]).copy_from_slice(Handshake.nonce.as_bytes());
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
		let mac_encoder_key: Secret = Secret::from_slice(&key_material[32..64]).expect("can create Secret from 32 bytes; qed");

		let mut egress_mac = Keccak::new_keccak256();
		let mut mac_material = H256::from_slice(&key_material[32..64]) ^ Handshake.remote_nonce;
		egress_mac.update(mac_material.as_bytes());
		egress_mac.update(&Handshake.auth_cipher);

		let mut ingress_mac = Keccak::new_keccak256();
		mac_material = H256::from_slice(&key_material[32..64]) ^ Handshake.nonce;
		ingress_mac.update(mac_material.as_bytes());
		ingress_mac.update(&Handshake.ack_cipher);

		return OriginatedEncryptedConnection {
			stream: stream,
			encoder: encoder,
			decoder: decoder,
			mac_encoder_key: mac_encoder_key,
			egress_mac: egress_mac,
			ingress_mac: ingress_mac,
		};
}
