use secp256k1::key::{PublicKey, SecretKey};
use tiny_keccak::Keccak;
use aes_ctr::Aes256Ctr;


pub struct OriginatedEncryptedConnection {
	pub public_key: PublicKey,
	pub encoder: Aes256Ctr,
	pub decoder: Aes256Ctr,
	pub mac_encoder_key: SecretKey,
	pub egress_mac: Keccak,
	pub ingress_mac: Keccak,
    pub expected:[u8; 12],
}
