use secp256k1::{self, ecdh, key};
use ethkey::{Error, Secret, Public, SECP256K1};


/// Agree on a shared secret
pub fn agree(secret: &Secret, public: &Public) -> Secret {
  let context = &SECP256K1;
  let pdata = {
    let mut temp = [4u8; 65];
    (&mut temp[1..65]).copy_from_slice(&public[0..64]);
    temp
  };

  let publ = key::PublicKey::from_slice(&pdata).unwrap();
  let sec = key::SecretKey::from_slice(secret.as_bytes()).unwrap();
  let shared = ecdh::SharedSecret::new(&publ, &sec);

  Secret::from_unsafe_slice(&shared[0..32]).unwrap()
}