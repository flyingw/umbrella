extern crate ethcore_network_devp2p;
extern crate ethkey;
extern crate ethereum_types;
extern crate keccak_hash;

use std::io::{Write, Read};
use std::str::FromStr;
use ethcore_network_devp2p::node_table::{Node};
use keccak_hash::write_keccak;
use std::net::TcpStream;
use ethereum_types::H256;
use ethkey::{Generator, KeyPair, Random, Secret, Public, sign};
use ethkey::crypto::{ecdh, ecies, Error};

fn main() {
	let enode: &str = "enode://16cabdd5c1049a54255a52ed775ee5ed1b4f3fd52bf25b751470a59bda8f093df563dc5d385103e46314ff5dacb8f37fcd988b20efc63b9b5fa78f5417971b48@127.0.0.1:30301";
	let node: Node = FromStr::from_str(enode).unwrap();

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
	let shared: H256 = *ecdh::agree(keys.secret(), &node.id).unwrap();
	sig.copy_from_slice(&*sign(ecdhe.secret(), &(shared ^ nonce)).unwrap());
	write_keccak(ecdhe.public(), hepubk);
	pubk.copy_from_slice(keys.public().as_bytes());
	dataNonce.copy_from_slice(nonce.as_bytes());
	
	let message: Vec<u8> = ecies::encrypt(&node.id, &[], &data).unwrap();
	// self.auth_cipher = message.clone();
	// self.connection.send(io, message);
	// self.connection.expect(V4_ACK_PACKET_SIZE);
	// self.state = HandshakeState::ReadingAck;
	
	const V4_ACK_PACKET_SIZE: usize = 210;

	let mut stream = TcpStream::connect(node.endpoint.address).unwrap();
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
