use aes_ctr::Aes128Ctr;
use aes_ctr::stream_cipher::NewStreamCipher;
use aes_ctr::stream_cipher::SyncStreamCipher;
use aes::block_cipher_trait::generic_array::GenericArray;
use hex;
use rust_scrypt::{scrypt, ScryptParams};
use secp256k1::{SecretKey};
use serde_json;

pub fn read_secret(json: &String, password: &String) -> SecretKey {
  let json: serde_json::Value = serde_json::from_str(&json).expect(&format!("failed to parse secret key json={:?}", &json));

  let version = get_u64(&json, &vec!["version"]);
  if version != 3 { panic!("unsupported secret key file version={}", version) };
  let cipher = get_string(&json, &vec!["crypto", "cipher"]);
  if cipher != "aes-128-ctr" { panic!("unsupported cipher={}", cipher) };
  let iv_hex = get_string(&json, &vec!["crypto", "cipherparams", "iv"]);
  let ciphertext_hex = get_string(&json, &vec!["crypto", "ciphertext"]);
  let kdf = get_string(&json, &vec!["crypto", "kdf"]);
  if kdf != "scrypt" { panic!("kdf={} is not supported", kdf) };
  let dklen = get_u64(&json, &vec!["crypto", "kdfparams", "dklen"]);
  if dklen != 32 { panic!("unsupported dklen={}", dklen); }
  let n = get_u64(&json, &vec!["crypto", "kdfparams", "n"]);
  let p = get_u64(&json, &vec!["crypto", "kdfparams", "p"]);
  let r = get_u64(&json, &vec!["crypto", "kdfparams", "r"]);
  let salt_hex = get_string(&json, &vec!["crypto", "kdfparams", "salt"]);

  let salt = hex::decode(&salt_hex).unwrap();
  let params = ScryptParams { n: n, r: r as u32, p: p as u32 };
  let mut secret_part: Vec<u8> = vec![0;32];
  scrypt(password.as_bytes(), &salt, &params, &mut secret_part);

  let iv = hex::decode(&iv_hex).unwrap();
  let ciphertext = hex::decode(&ciphertext_hex).unwrap();
  let mut secret_key: Vec<u8> = vec![0;ciphertext.len()];

  let mut enc = Aes128Ctr::new(
		GenericArray::from_slice(&secret_part[0..16]),
		GenericArray::from_slice(&iv),
	);
	secret_key.copy_from_slice(&ciphertext);
	enc.try_apply_keystream(&mut secret_key).unwrap();

  SecretKey::from_slice(&secret_key).unwrap()
}

fn get_string(v: &serde_json::Value, path: &Vec<&str>) -> String {
    let mut curr = v;
    for p in path {
        curr = curr.get(p).expect(&format!("missing {}", p));
    };
    curr.as_str().expect(&format!("{} not a string", path.join("."))).to_string()
}

fn get_u64(v: &serde_json::Value, path: &Vec<&str>) -> u64 {
    let mut curr = v;
    for p in path {
        curr = curr.get(p).expect(&format!("missing {}", p));
    };
    curr.as_u64().expect(&format!("{} not a as_u64", path.join(".")))
}