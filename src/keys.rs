use secp256k1::recovery::{RecoverableSignature};
use secp256k1::{Message, Secp256k1, Error};
use secp256k1::key::{SecretKey, PublicKey};
use crate::hash256::Hash256;

pub type Signature = [u8; 65];

pub fn slice_to_public(d: &[u8]) -> Result<PublicKey, Error> {
	if d.len() < 64 { return Err(Error::InvalidSecretKey) }
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
	let signature: RecoverableSignature = secp.sign_recoverable(message, &secret_key);
	let (rec_id, data) = signature.serialize_compact();
	let mut data_arr: Signature = [0; 65];

	// no need to check if s is low, it always is
	data_arr[0..64].copy_from_slice(&data[0..64]);
	data_arr[64] = rec_id.to_i32() as u8;
	return data_arr;
}
