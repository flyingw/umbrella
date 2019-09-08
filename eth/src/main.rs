extern crate ethkey;
extern crate ethereum_types;
extern crate keccak_hash;
extern crate parity_crypto;
extern crate tiny_keccak;
extern crate secp256k1;
extern crate rand;
extern crate rlp;
extern crate parity_snappy;
extern crate common_types;
extern crate ethstore;

mod connection;
mod eth_protocol;

use common_types::transaction::{Transaction, SignedTransaction, Action};
use ethereum_types::{U256};
use ethkey::{Generator, Random, sign, Secret, Public, KeyPair, Address, Password};
use ethkey::crypto::{ecdh, ecies};
use ethstore::account::{Crypto, Kdf, Scrypt};
use ethstore::json;
use keccak_hash::{keccak, write_keccak};
use parity_crypto::aes::{AesCtr256, AesEcb256};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use connection::{RemoteNode, OriginatedConnection, OriginatedEncryptedConnection};
use eth_protocol::EthProtocol;

fn main() {
	let enode: &str = "enode://16cabdd5c1049a54255a52ed775ee5ed1b4f3fd52bf25b751470a59bda8f093df563dc5d385103e46314ff5dacb8f37fcd988b20efc63b9b5fa78f5417971b48@127.0.0.1:30301";
	let node: RemoteNode = RemoteNode::parse(enode).unwrap();
	let connection: OriginatedConnection = OriginatedConnection::new(node);
	let connection: OriginatedEncryptedConnection = OriginatedEncryptedConnection::new(connection);
	let mut protocol: EthProtocol = EthProtocol::new(connection);
	protocol.write_hello();
	protocol.read_hello();
	protocol.read_packet();
	let file = File::open("secret_keyfile").unwrap();
	let keyfile = json::KeyFile::load(&file).unwrap();
	let qwe = Crypto::from(keyfile.crypto);
	let c: Crypto = Crypto::from(qwe);
	let password = Password::from("test");
	let secret = c.secret(&password).unwrap();
	// let secret = Secret::from_str("ee5ae874c0e346ba986801a16745920b8eb49fe2f21d8c15b362c552ae7d6d41").unwrap();	
	let t = Transaction {
		nonce: U256::from(2),
		gas_price: U256::from(1_000_000_000u64),
		gas: U256::from(21_000),
		action: Action::Call(Address::from_str("448e67382b81db59f6cd35ccf4df7f774930a05a").unwrap()),
		value: U256::from(10),
		data: Vec::new(),
	};
	let singedTransaction = t.sign(&secret, Some(123));
	protocol.write_transactions(&vec![&singedTransaction]);
	loop {
		protocol.read_packet();
		thread::sleep(Duration::from_millis(3000));
		protocol.write_ping();
	}
}
