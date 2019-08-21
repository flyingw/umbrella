use super::address::AddressType;
use super::network::Network;
use rust_base58::base58::{FromBase58, ToBase58};
pub use super::hash160::Hash160;
pub use super::hash256::sha256d;
use super::result::{Error, Result};

/// Converts a public key hash to its legacy address
pub fn legacyaddr_encode(hash160: &Hash160, addr_type: AddressType, network: Network) -> String {
    let mut v = Vec::with_capacity(1 + hash160.0.len() + 2);
    v.push(match addr_type {
        AddressType::P2PKH => network.legacyaddr_pubkeyhash_flag(),
        AddressType::P2SH => network.legacyaddr_script_flag(),
    });
    v.extend_from_slice(&hash160.0);
    let checksum = sha256d(&v).0;
    v.push(checksum[0]);
    v.push(checksum[1]);
    v.push(checksum[2]);
    v.push(checksum[3]);
    let b: &[u8] = v.as_ref();
    b.to_base58()
}

/// Decodes a legacy address to a public key hash
pub fn legacyaddr_decode(input: &str, network: Network) -> Result<(Hash160, AddressType)> {
    // Make sure addr is at least some minimum to verify checksum and addr type
    // We will check the private key size later.
    let v = input.from_base58()?;
    if v.len() < 6 {
        let msg = format!("Base58 address not long enough: {}", v.len());
        return Err(Error::BadData(msg));
    }

    // Verify checksum
    let v0 = &v[0..v.len() - 4];
    let v1 = &v[v.len() - 4..v.len()];
    let cs = sha256d(v0).0;
    if v1[0] != cs[0] || v1[1] != cs[1] || v1[2] != cs[2] || v1[3] != cs[3] {
        let msg = format!("Bad checksum: {:?} != {:?}", &cs[..4], v1);
        return Err(Error::BadData(msg));
    }

    // Extract address type
    let addr_type_byte = v0[0];
    let addr_type = if addr_type_byte == network.legacyaddr_pubkeyhash_flag() {
        AddressType::P2PKH
    } else if addr_type_byte == network.legacyaddr_script_flag() {
        AddressType::P2SH
    } else {
        let msg = format!("Unknown address type {}", addr_type_byte);
        return Err(Error::BadData(msg));
    };

    // Extract hash160 address and return
    if v0.len() != 21 {
        let msg = format!("Hash160 address not long enough: {}", v0.len() - 1);
        return Err(Error::BadData(msg));
    }
    let mut hash160addr = [0; 20];
    hash160addr.clone_from_slice(&v0[1..]);
    Ok((Hash160(hash160addr), addr_type))
}
