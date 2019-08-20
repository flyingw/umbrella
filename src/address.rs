//! Address encoding and decoding

/// Address type which is either P2PKH or P2SH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-public-key-hash address
    P2PKH,
    /// Pay-to-script-hash address
    P2SH,
}
