use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1, Error};
use secp256k1::ecdh::{SharedSecret};
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::constants::SECRET_KEY_SIZE;
// use ethereum_types::{H256, H512};
use rand::rngs::OsRng;
use rand::RngCore;
// use std::convert::From;
use crate::hash256::{Hash256};

// // pub type SecretKey = H256;
// // pub type PublicKey = H512;
pub type Signature = [u8; 65];
// pub type Message = Hash256;

pub struct KeyPair {
	secret: SecretKey,
	public: PublicKey,
}

lazy_static! {
	pub static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

pub fn slice_to_public(d: &[u8]) -> Result<PublicKey, Error> {
	if (d.len() < 64) { return Err(Error::InvalidSecretKey) }
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

impl KeyPair {
// 	pub fn from_secret(secret: SecretKey) -> KeyPair {
// 		let secp_secret: key::SecretKey = key::SecretKey::from_slice(&secret[..]).unwrap();
// 		let secp_public = key::PublicKey::from_secret_key(&SECP256K1, &secp_secret);
// 		let secp_uncompressed = secp_public.serialize_uncompressed();
// 		let mut public: PublicKey = PublicKey::default();
// 		public.as_bytes_mut().copy_from_slice(&secp_uncompressed[1..65]);
// 		let keypair = KeyPair {
// 			secret: secret,
// 			public: public,
// 		};
// 		return keypair;
// 	}

//   pub fn from_keypair(secp_secret: key::SecretKey, secp_public: key::PublicKey) -> KeyPair {
// 		// let context: &Secp256k1<secp256k1::All> = &SECP256K1;
// 		let secp_uncompressed = secp_public.serialize_uncompressed();
// 		let secret: SecretKey = secret_from(sec);
// 		let mut public: PublicKey = PublicKey::default();
// 		public.as_bytes_mut().copy_from_slice(&secp_uncompressed[1..65]);
//     let keypair = KeyPair {
// 			secret: secret,
// 			public: public,
// 		};
//     return keypair;
// 	}

  // pub fn random() -> KeyPair {
  //   let mut rng = OsRng::new().unwrap();
  //   let (secret, public) = SECP256K1.generate_keypair(&mut rng);
  //   KeyPair {
  //     secret: secret,
  //     public: public
  //   }
  //   // return KeyPair::from_keypair(sec, publ);
  // }

  pub fn secret(&self) -> &SecretKey {
		&self.secret
	}

	// pub fn public(&self) -> &PublicKey {
	// 	&self.public
	// }
}

// fn secret_from(sec_key: key::SecretKey) -> SecretKey {
//   let mut a = [0; SECRET_KEY_SIZE];
//   a.copy_from_slice(&sec_key[0 .. SECRET_KEY_SIZE]);
//   a.into()
// }

pub fn sign(secret: &SecretKey, message: &Message) -> Signature {
	let context: &Secp256k1<secp256k1::All> = &SECP256K1;
	// let secret_key: key::SecretKey = key::SecretKey::from_slice(secret.as_ref()).unwrap();
	let message: &secp256k1::Message = &secp256k1::Message::from_slice(&message[..]).unwrap();
	let signature: RecoverableSignature = context.sign_recoverable(message, &secret);
	// let signature = context.sign_recoverable(&secp256k1::Message::from_slice(&message[..])?, &secret_key).unwrap();
	let (rec_id, data) = signature.serialize_compact();
	let mut data_arr: Signature = [0; 65];

	// no need to check if s is low, it always is
	data_arr[0..64].copy_from_slice(&data[0..64]);
	data_arr[64] = rec_id.to_i32() as u8;
	return data_arr;
}

// // pub fn verify_public(public: &PublicKey, signature: &Signature, message: &Message) -> Result<bool, Error> {
// // 	let context = &SECP256K1;
// // 	let rsig = RecoverableSignature::from_compact(context, &signature[0..64], RecoveryId::from_i32(signature[64] as i32)?)?;
// // 	let sig = rsig.to_standard(context);

// // 	let pdata: [u8; 65] = {
// // 		let mut temp = [4u8; 65];
// // 		temp[1..65].copy_from_slice(public.as_bytes());
// // 		temp
// // 	};

// // 	let publ = secp256k1::PublicKey::from_slice(&pdata).unwrap();
// // 	match context.verify(&secp256k1::Message::from_slice(&message[..])?, &sig, &publ) {
// // 		Ok(_) => Ok(true),
// // 		Err(SecpError::IncorrectSignature) => Ok(false),
// // 		Err(x) => Err(Error::from(x))
// // 	}
// // }

/// ECDH functions
/// Agree on a shared secret
pub fn agree(secret_key: &SecretKey, public_key: &PublicKey) -> SecretKey {
  let context = &SECP256K1;
  // let pdata = {
  //   let mut temp = [4u8; 65];
  //   (&mut temp[1..65]).copy_from_slice(&public_key[0..64]);
  //   temp
  // };
  // let key_public_key = key::PublicKey::from_slice(&pdata).unwrap();
  // let key_secret_key = key::SecretKey::from_slice(secret.as_bytes()).unwrap();
  // SharedSecret::new(&public_key, &secret_key)
  panic!("example")
}

// #[cfg(test)]
// mod tests {
// 	use std::str::FromStr;
// 	use {KeyPair, SecretKey};

// 	#[test]
// 	fn from_secret() {
// 		let secret = SecretKey::from_str("a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65").unwrap();
// 		let _ = KeyPair::from_secret(secret).unwrap();
// 	}

// 	#[test]
// 	fn signature_to_and_from_str() {
// 		let keypair = KeyPair.random();
// 		let message = Message::default();
// 		let signature = sign(keypair.secret(), &message).unwrap();
// 		let string = format!("{}", signature);
// 		let deserialized = Signature::from_str(&string).unwrap();
// 		assert_eq!(signature, deserialized);
// 	}

// 	#[test]
// 	fn sign_and_recover_public() {
// 		let keypair = KeyPair.random();
// 		let message = Message::default();
// 		let signature = sign(keypair.secret(), &message).unwrap();
// 		assert_eq!(keypair.public(), &recover(&signature, &message).unwrap());
// 	}

// 	#[test]
// 	fn sign_and_verify_public() {
// 		let keypair = KeyPair.random();
// 		let message = Message::default();
// 		let signature = sign(keypair.secret(), &message).unwrap();
// 		assert!(verify_public(keypair.public(), &signature, &message).unwrap());
// 	}
// }
