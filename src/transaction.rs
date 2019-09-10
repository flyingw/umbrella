use secp256k1::{Message, Secp256k1, SecretKey};
use super::hash256::Hash256;
use super::result::Result;

/// Generates a signature for a transaction sighash
pub fn generate_signature(
    private_key: &[u8; 32],
    sighash: &Hash256,
    sighash_type: u8,
) -> Result<Vec<u8>> {
    let secp = Secp256k1::signing_only();
    let message = Message::from_slice(&sighash.0)?;
    let secret_key = SecretKey::from_slice(private_key)?;
    let mut signature = secp.sign(&message, &secret_key);
    signature.normalize_s();
    let mut sig = signature.serialize_der().to_vec();
    sig.push(sighash_type);
    Ok(sig)
}
