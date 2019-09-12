use ethereum_types::{U256};
use common_types::transaction::{SignedTransaction};
use rlp::{RlpStream, Rlp, Encodable, EMPTY_LIST_RLP};
use crate::keys::{public_to_slice};
use crate::connection::{OriginatedEncryptedConnection, RLPX_TRANSPORT_PROTOCOL_VERSION};

const CLIENT_NAME: &str = "umbrella";
const LOCAL_PORT: u16 = 1234;

const PACKET_HELLO: u8 = 0x80; // actually 0x00 rlp doc "The integer 0 = [ 0x80 ]"
const PACKET_PING: u8 = 0x02;
const PACKET_PONG: u8 = 0x03;
const PACKET_USER: u8 = 0x10;
const PACKET_STATUS: u8 = 0x00 + PACKET_USER;
const PACKET_TRANSACTIONS: u8 = 0x02 + PACKET_USER;
const PACKET_NEW_BLOCK: u8 = 0x07 + PACKET_USER;

pub struct EthProtocol {
	connection: OriginatedEncryptedConnection,
}

impl EthProtocol {
	pub fn new(connection: OriginatedEncryptedConnection) -> EthProtocol {
		EthProtocol { connection: connection }
	}

	pub fn write_hello(&mut self) -> () {
		let mut rlp = RlpStream::new();
		let u_public_key = &public_to_slice(&self.connection.public_key)[..];
		rlp.append_raw(&[PACKET_HELLO], 0)
		  .begin_list(5)
			.append(&RLPX_TRANSPORT_PROTOCOL_VERSION)
			.append(&CLIENT_NAME)
			.append_list(&vec!(ETH_63_CAPABILITY))
			.append(&LOCAL_PORT)
			.append(&u_public_key);
		self.connection.write_packet(&rlp.out());
	}

	pub fn read_hello(&mut self) -> () {
		self.connection.read_packet().map(|packet| {
			match packet.first() {
				Some(&PACKET_HELLO) => {
					let rlp = Rlp::new(&packet[1..]);
					let peer_caps: Rlp = rlp.at(2).unwrap();

					peer_caps.is_list();
					peer_caps.item_count().unwrap();

					let peer_cap = peer_caps.at(0).unwrap();

					let p: u8 = peer_cap.val_at(1).unwrap();

					println!("hello from remote! peer_caps={:?}", p);
				},
				Some(msg) => panic!("not a hello message id={}, expect={}", msg, PACKET_HELLO),
				None => panic!("empty hello message"),
			}
		}).unwrap();
	}

	pub fn write_ping(&mut self) -> () {
		self.write_packet(PACKET_PING, &EMPTY_LIST_RLP);
	}
	
	pub fn write_transactions(&mut self, transactions: &Vec<&SignedTransaction>) -> () {
		let mut rlp = RlpStream::new_list(transactions.len());
		for t in transactions {
			rlp.append(*t);
		}
		self.write_packet(PACKET_TRANSACTIONS, &rlp.out());
	}

	pub fn write_packet(&mut self, packet_id: u8, data: &[u8]) -> () {
		let mut rlp = RlpStream::new();
		rlp.append(&(u32::from(packet_id)));
		let mut compressed = Vec::new();
		let len = parity_snappy::compress_into(data, &mut compressed);
		let payload = &compressed[0..len];
		rlp.append_raw(payload, 1);
		self.connection.write_packet(&rlp.out());
	}

	pub fn read_packet(&mut self) -> () {
		let res: Option<Vec<u8>> = self.connection.read_packet();
		let data: &[u8] = match res {
			Some(ref data) if data.len() > 1 => data,
			Some(data) => panic!("broken packet={:?}", &data),
			None => return,
		};
		let packet_id: u8 = data[0];
		let compressed: &[u8] = &data[1..];
		let packet: Vec<u8> = parity_snappy::decompress(compressed).unwrap();
		let rlp: Rlp = Rlp::new(&packet);
		match packet_id {
			PACKET_PING => println!("ping packet"),
			PACKET_PONG => println!("pong packet"),
			PACKET_STATUS => {
				let protocol_version: u8 = rlp.val_at(0).unwrap();
				let network_id: u64 = rlp.val_at(1).unwrap();
				let difficulty: U256 = rlp.val_at(2).unwrap();
				let latest_hash: Vec<u8> = rlp.val_at(3).unwrap();
				let genesis: Vec<u8> = rlp.val_at(4).unwrap();

				println!("status packet. protocol_version={}, network_id={}, difficulty={:?}, latest_hash={:?}, genesis={:?}", protocol_version, network_id, difficulty.0, latest_hash, &genesis);


				let mut rlp = RlpStream::new_list(5);
				rlp.append(&protocol_version)
					.append(&network_id)
					.append(&difficulty)
					.append(&latest_hash)
					.append(&genesis);
				self.write_packet(PACKET_STATUS, &rlp.out());
			},
			PACKET_TRANSACTIONS => println!("transactions packet"),
			PACKET_NEW_BLOCK => println!("new block packet"),
			_ => println!("unknown packet={}", packet_id),
		}
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
pub const ETH_63_CAPABILITY: CapabilityInfo = CapabilityInfo { 
	protocol: ETH_PROTOCOL,
	version: ETH_PROTOCOL_VERSION_63.0,
	packet_count: ETH_PROTOCOL_VERSION_63.1
};
