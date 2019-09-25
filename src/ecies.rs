use parity_crypto::{aes, digest, hmac, is_equal};
use ethereum_types::H128;
use rand;
use secp256k1::{self, ecdh};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use crate::keys::{public_to_slice, slice_to_public};

fn hash(output: &mut [u8], x: &[u8], _y: &[u8]) -> i32 {
  kdf(&x, &[0u8; 0], output);
  1
}

/// Encrypt a message with a public key, writing an HMAC covering both
/// the plaintext and authenticated data.
///
/// Authenticated data may be empty.
pub fn encrypt(public_key: &PublicKey, auth_data: &[u8], plain: &[u8]) -> Result<Vec<u8>, u8> {
  let mut rng = rand::thread_rng();
  let secp = Secp256k1::new();
  let (secret_key_rand, public_key_rand) = secp.generate_keypair(&mut rng);

  let key = ecdh::SharedSecret::new_with_hash(&public_key, &secret_key_rand, &mut hash);

  let ekey = &key[0..16];
  let mkey = hmac::SigKey::sha256(&digest::sha256(&key[16..32]));

  let mut msg = vec![0u8; 1 + 64 + 16 + plain.len() + 32];
  msg[0] = 0x04u8;
  {
    let msgd = &mut msg[1..];
    msgd[0..64].copy_from_slice(&public_to_slice(&public_key_rand));
    let iv = H128::random();
    msgd[64..80].copy_from_slice(iv.as_bytes());
    {
      let cipher = &mut msgd[(64 + 16)..(64 + 16 + plain.len())];
      aes::encrypt_128_ctr(ekey, iv.as_bytes(), plain, cipher).unwrap();
    }
    let mut hmac = hmac::Signer::with(&mkey);
    {
      let cipher_iv = &msgd[64..(64 + 16 + plain.len())];
      hmac.update(cipher_iv);
    }
    hmac.update(auth_data);
    let sig = hmac.sign();
    msgd[(64 + 16 + plain.len())..].copy_from_slice(&sig);
  }
  Ok(msg)
}

/// Decrypt a message with a secret key, checking HMAC for ciphertext
/// and authenticated data validity.
pub fn decrypt(secret_key: &SecretKey, auth_data: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, u8> {
  let meta_len = 1 + 64 + 16 + 32;
  if encrypted.len() < meta_len  || encrypted[0] < 2 || encrypted[0] > 4 {
    panic!("decrypt error=InvalidMessage, invalid message: publickey");
  }

  let e = &encrypted[1..];
  let public_key = slice_to_public(&e[0..64]).unwrap();
  let key = ecdh::SharedSecret::new_with_hash(&public_key, &secret_key, &mut hash);
  
  let ekey = &key[0..16];
  let mkey = hmac::SigKey::sha256(&digest::sha256(&key[16..32]));

  let clen = encrypted.len() - meta_len;
  let cipher_with_iv = &e[64..(64+16+clen)];
  let cipher_iv = &cipher_with_iv[0..16];
  let cipher_no_iv = &cipher_with_iv[16..];
  let msg_mac = &e[(64+16+clen)..];

  // Verify tag
  let mut hmac = hmac::Signer::with(&mkey);
  hmac.update(cipher_with_iv);
  hmac.update(auth_data);
  let mac = hmac.sign();

  if !is_equal(&mac.as_ref()[..], msg_mac) {
    panic!("decrypt error=InvalidMessage, wrong mac");
  }

  let mut msg = vec![0u8; clen];
  aes::decrypt_128_ctr(ekey, cipher_iv, cipher_no_iv, &mut msg[..]).unwrap();
  Ok(msg)
}

fn kdf(shared: &[u8], s1: &[u8], dest: &mut [u8]) {
  // SEC/ISO/Shoup specify counter size SHOULD be equivalent
  // to size of hash output, however, it also notes that
  // the 4 bytes is okay. NIST specifies 4 bytes.
  let mut ctr = 1u32;
  let mut written = 0usize;
  while written < dest.len() {
    let mut hasher = digest::Hasher::sha256();
    let ctrs = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];
    hasher.update(&ctrs);
    hasher.update(&shared[..]);
    hasher.update(s1);
    let d = hasher.finish();
    &mut dest[written..(written + 32)].copy_from_slice(&d);
    written += 32;
    ctr += 1;
  }
}