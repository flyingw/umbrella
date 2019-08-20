//! Pay-to-public-key-hash transaction scripts

use super::script::op_codes::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_PUSH};
use super::script::{next_op, Script};
use super::result::{Error, Result};
pub use super::hash160::Hash160;

/// Creates the pubkey script to send to an address
pub fn create_pk_script(address: &Hash160) -> Script {
    let mut script = Script::new();
    script.append(OP_DUP);
    script.append(OP_HASH160);
    script.append_data(&address.0);
    script.append(OP_EQUALVERIFY);
    script.append(OP_CHECKSIG);
    script
}

/// Creates a sigscript to sign a p2pkh transaction
pub fn create_sig_script(sig: &[u8], public_key: &[u8; 33]) -> Script {
    let mut sig_script = Script::new();
    sig_script.append_data(sig);
    sig_script.append_data(public_key);
    sig_script
}

/// Returns whether the pk_script is p2pkh
pub fn check_pk_script(pk_script: &[u8]) -> bool {
    pk_script.len() == 25
        && pk_script[0] == OP_DUP
        && pk_script[1] == OP_HASH160
        && pk_script[2] == OP_PUSH + 20
        && pk_script[23] == OP_EQUALVERIFY
        && pk_script[24] == OP_CHECKSIG
}

/// Returns whether the sig_script is p2pkh
pub fn check_sig_script(sig_script: &[u8]) -> bool {
    if sig_script.len() == 0 || sig_script[0] < OP_PUSH + 71 || sig_script[0] > OP_PUSH + 73 {
        return false;
    }
    let i = next_op(0, &sig_script);
    if i >= sig_script.len() || sig_script[i] != OP_PUSH + 33 && sig_script[i] != OP_PUSH + 65 {
        return false;
    }
    next_op(i, &sig_script) >= sig_script.len()
}

/// Returns whether the pk_script is a P2PKH send to the provided address
pub fn check_pk_script_addr(hash160: &Hash160, pk_script: &[u8]) -> bool {
    check_pk_script(pk_script) && pk_script[3..23] == hash160.0
}

/// Returns whether the sig_script contains our public key
pub fn check_sig_script_addr(pubkey: &[u8], sig_script: &[u8]) -> bool {
    if !check_sig_script(sig_script) {
        return false;
    }
    let i = next_op(0, &sig_script);
    sig_script[i + 1..] == *pubkey
}

/// Returns the public key this sig_script was sent from
pub fn extract_pubkey(sig_script: &[u8]) -> Result<Vec<u8>> {
    if !check_sig_script(sig_script) {
        let msg = "Script is not a sigscript for P2PKH".to_string();
        return Err(Error::BadData(msg));
    }
    let i = next_op(0, &sig_script);
    Ok(sig_script[i + 1..].to_vec())
}

/// Returns the address this pk_script sends to
pub fn extract_pubkeyhash(pk_script: &[u8]) -> Result<Hash160> {
    if check_pk_script(pk_script) {
        let mut hash160 = Hash160([0; 20]);
        hash160.0.clone_from_slice(&pk_script[3..23]);
        return Ok(hash160);
    } else {
        return Err(Error::BadData("Script is not a standard P2PKH".to_string()));
    }
}
