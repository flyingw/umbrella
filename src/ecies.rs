use rand;
use rand::RngCore;
use secp256k1::{self, ecdh};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use crate::keys::{public_to_slice, slice_to_public};
use aes_ctr::Aes128Ctr;
use aes_ctr::stream_cipher::NewStreamCipher;
use aes_ctr::stream_cipher::SyncStreamCipher;
use aes::block_cipher_trait::generic_array::GenericArray;
use ring::digest::{digest, SHA256};
use ring::{hmac};

/// Encrypt a message with a public key, writing an HMAC covering both
/// the plaintext and authenticated data.
///
/// Authenticated data may be empty.
pub fn encrypt(public_key: &PublicKey, auth_data: &[u8], plain: &[u8]) -> Result<Vec<u8>, u8> {
  let mut rng = rand::thread_rng();
  let secp = Secp256k1::new();
  let (secret_key_rand, public_key_rand) = secp.generate_keypair(&mut rng);

  let mut key = [0u8; 32];
  kdf(&ecdh::shared_secret_point(&public_key, &secret_key_rand)[..32], &[0u8; 0], &mut key);

  let ekey = &key[0..16];;
  let mkey = hmac::Key::new(hmac::HMAC_SHA256, digest(&SHA256, &key[16..32]).as_ref());

  let mut msg = vec![0u8; 1 + 64 + 16 + plain.len() + 32];
  msg[0] = 0x04u8;
  {
    let msgd = &mut msg[1..];
    msgd[0..64].copy_from_slice(&public_to_slice(&public_key_rand));
    let mut iv = [0u8;16];
    rng.fill_bytes(&mut iv);
    msgd[64..80].copy_from_slice(&iv);
    {
      let cipher = &mut msgd[(64 + 16)..(64 + 16 + plain.len())];
      let mut enc = Aes128Ctr::new(GenericArray::from_slice(ekey), GenericArray::from_slice(&iv));
      cipher[..plain.len()].copy_from_slice(plain);
	    enc.try_apply_keystream(cipher).unwrap();
    }
    let mut msg_hmac = vec![];
    {
      let cipher_iv = &msgd[64..(64 + 16 + plain.len())];
      msg_hmac.extend(cipher_iv);
    }
    msg_hmac.extend(auth_data);
    let sig = hmac::sign(&mkey, &msg_hmac);
    msgd[(64 + 16 + plain.len())..].copy_from_slice(sig.as_ref());
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
  let mut key = [0u8; 32];
  kdf(&ecdh::shared_secret_point(&public_key, &secret_key)[..32], &[0u8; 0], &mut key);
  
  let ekey = &key[0..16];
  let mkey = hmac::Key::new(hmac::HMAC_SHA256, digest(&SHA256, &key[16..32]).as_ref());

  let clen = encrypted.len() - meta_len;
  let cipher_with_iv = &e[64..(64+16+clen)];
  let cipher_iv = &cipher_with_iv[0..16];
  let cipher_no_iv = &cipher_with_iv[16..];
  let msg_mac = &e[(64+16+clen)..];

  // Verify tag
  let mut msg_hmac = vec![];
  msg_hmac.extend(cipher_with_iv);
  msg_hmac.extend(auth_data);
  let mac = hmac::sign(&mkey, &msg_hmac);

  if !(&mac.as_ref()[..] == msg_mac) {
    panic!("decrypt error=InvalidMessage, wrong mac");
  }

  let mut msg = vec![0u8; clen];
  let mut enc = aes_ctr::Aes128Ctr::new(GenericArray::from_slice(ekey), GenericArray::from_slice(cipher_iv));
	msg[..cipher_no_iv.len()].copy_from_slice(cipher_no_iv);
	enc.try_apply_keystream(&mut msg).unwrap();
  Ok(msg)
}

fn kdf(shared: &[u8], s1: &[u8], dest: &mut [u8]) {
  // SEC/ISO/Shoup specify counter size SHOULD be equivalent
  // to size of hash output, however, it also notes that
  // the 4 bytes is okay. NIST specifies 4 bytes.
  let mut ctr = 1u32;
  let mut written = 0usize;
  while written < dest.len() {
    let ctrs = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];
    let mut buf: Vec<u8> = vec![];
    buf.extend(&ctrs);
    buf.extend(&shared[..]);
    buf.extend(s1);
    let d = digest(&SHA256, &buf);
    &mut dest[written..(written + 32)].copy_from_slice(d.as_ref());
    written += 32;
    ctr += 1;
  }
}