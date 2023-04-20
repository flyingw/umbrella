use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, Error, SecretKey, PublicKey};
use tiny_keccak::Keccak;
use crate::hash256::Hash256;

pub type Signature = [u8; 65];
pub type Address = [u8; 20];

pub fn slice_to_public(d: &[u8]) -> Result<PublicKey, Error> {
	if d.len() < 64 { return Err(Error::InvalidPublicKey) }
	let mut x = [0u8; 65];
	x[0] = 4u8;
	x[1..65].copy_from_slice(&d[0..64]);
	PublicKey::from_slice(&x)
}

pub fn public_to_slice(public_key: &PublicKey) -> [u8;64] {
	let mut res = [0u8;64];
	res.copy_from_slice(&public_key.serialize_uncompressed()[1..65]);
	res
}

pub fn sign(secret_key: &SecretKey, message: &Hash256) -> Signature {
	let secp = Secp256k1::new();
	let message: &Message = &Message::from_slice(&message[..]).unwrap();
	let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(message, &secret_key);
	let (rec_id, data) = signature.serialize_compact();
	let mut data_arr: Signature = [0; 65];

	// no need to check if s is low, it always is
	data_arr[0..64].copy_from_slice(&data[0..64]);
	data_arr[64] = rec_id.to_i32() as u8;
	return data_arr;
}

pub fn recover(signature: &Signature, message: &Hash256) -> PublicKey {
	let secp = Secp256k1::new();
	let recover_id = RecoveryId::from_i32(signature[64] as i32).unwrap();
	let message = Message::from_slice(&message[..]).unwrap();
	let rsig: RecoverableSignature = RecoverableSignature::from_compact(&signature[0..64], recover_id).unwrap();
	secp.recover_ecdsa(&message, &rsig).unwrap()
}

pub fn public_to_address(public: &PublicKey) -> Address {
	let mut result = [0u8; 32];
	Keccak::keccak256(&public_to_slice(public), &mut result);
	let mut res: Address = [0u8; 20];
	res.copy_from_slice(&result[12..]);
	res
}