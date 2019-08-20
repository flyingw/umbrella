use byteorder::{BigEndian, WriteBytesExt};
use crate::network::Network;
use ring::digest::SHA512;
use ring::hmac;
use rust_base58::base58::{FromBase58, ToBase58};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use std::slice;
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::hash256::sha256d;
use crate::hash160::hash160;

/// Maximum private key value (exclusive)
const SECP256K1_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Index which begins the derived hardened keys
pub const HARDENED_KEY: u32 = 2147483648;

/// "xpub" prefix for public extended keys on mainnet
pub const MAINNET_PUBLIC_EXTENDED_KEY: u32 = 0x0488B21E;
/// "xprv" prefix for private extended keys on mainnet
pub const MAINNET_PRIVATE_EXTENDED_KEY: u32 = 0x0488ADE4;
/// "tpub" prefix for public extended keys on testnet
pub const TESTNET_PUBLIC_EXTENDED_KEY: u32 = 0x043587C;
/// "tprv" prefix for private extended keys on testnet
pub const TESTNET_PRIVATE_EXTENDED_KEY: u32 = 0x04358394;
/// "tpub" prefix for public extended keys on regtest
pub const REGTEST_PUBLIC_EXTENDED_KEY: u32 = 0x043587CF;
/// "tprv" prefix for private extended keys on regtest
pub const REGTEST_PRIVATE_EXTENDED_KEY: u32 = 0x04358394;

/// Public or private key type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ExtendedKeyType {
    Public,
    Private,
}

/// A private or public key in an hierarchial deterministic wallet
#[derive(Clone, Copy)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Creates a new extended public key
    pub fn new_public_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        public_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if public_key.len() != 33 {
            return Err(Error::BadArgument("Public key must be len 33".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet => c
                    .write_u32::<BigEndian>(TESTNET_PUBLIC_EXTENDED_KEY)
                    .unwrap(),
                Network::Regtest => c
                    .write_u32::<BigEndian>(REGTEST_PUBLIC_EXTENDED_KEY)
                    .unwrap()
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write(public_key).unwrap();
        }
        Ok(extended_key)
    }

    /// Creates a new extended private key
    pub fn new_private_key(
        network: Network,
        depth: u8,
        parent_fingerprint: &[u8],
        index: u32,
        chain_code: &[u8],
        private_key: &[u8],
    ) -> Result<ExtendedKey> {
        if parent_fingerprint.len() != 4 {
            return Err(Error::BadArgument("Fingerprint must be len 4".to_string()));
        }
        if chain_code.len() != 32 {
            return Err(Error::BadArgument("Chain code must be len 32".to_string()));
        }
        if private_key.len() != 32 {
            return Err(Error::BadArgument("Private key must be len 32".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        {
            let mut c = Cursor::new(&mut extended_key.0 as &mut [u8]);
            match network {
                Network::Mainnet => c
                    .write_u32::<BigEndian>(MAINNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
                Network::Testnet => c
                    .write_u32::<BigEndian>(TESTNET_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
                Network::Regtest => c
                    .write_u32::<BigEndian>(REGTEST_PRIVATE_EXTENDED_KEY)
                    .unwrap(),
            }
            c.write_u8(depth).unwrap();
            c.write(parent_fingerprint).unwrap();
            c.write_u32::<BigEndian>(index).unwrap();
            c.write(chain_code).unwrap();
            c.write_u8(0).unwrap();
            c.write(private_key).unwrap();
        }
        Ok(extended_key)
    }

    /// Gets the extended key version byte prefix
    pub fn version(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | ((self.0[3] as u32) << 0)
    }

    /// Gets the network
    pub fn network(&self) -> Result<Network> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == MAINNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Mainnet);
        } else if ver == TESTNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Testnet);
        } else if ver == REGTEST_PUBLIC_EXTENDED_KEY || ver == REGTEST_PRIVATE_EXTENDED_KEY {
            return Ok(Network::Regtest)
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
        }
    }

    /// Gets the key type
    pub fn key_type(&self) -> Result<ExtendedKeyType> {
        let ver = self.version();
        if ver == MAINNET_PUBLIC_EXTENDED_KEY || ver == TESTNET_PUBLIC_EXTENDED_KEY || ver == REGTEST_PUBLIC_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Public);
        } else if ver == MAINNET_PRIVATE_EXTENDED_KEY || ver == TESTNET_PRIVATE_EXTENDED_KEY  || ver == REGTEST_PRIVATE_EXTENDED_KEY {
            return Ok(ExtendedKeyType::Private);
        } else {
            let msg = format!("Unknown extended key version {:?}", ver);
            return Err(Error::BadData(msg));
        }
    }

    /// Gets the depth
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Gets the first 4 bytes of the parent key, or 0 if this is the master key
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        [self.0[5], self.0[6], self.0[7], self.0[8]]
    }

    /// Get the index of this key as derived from the parent
    pub fn index(&self) -> u32 {
        ((self.0[9] as u32) << 24)
            | ((self.0[10] as u32) << 16)
            | ((self.0[11] as u32) << 8)
            | ((self.0[12] as u32) << 0)
    }

    /// Gets the chain code
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0; 32];
        chain_code.clone_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Gets the public key if this is an extended public key
    pub fn public_key(&self) -> Result<[u8; 33]> {
        match self.key_type()? {
            ExtendedKeyType::Public => {
                let mut public_key = [0; 33];
                public_key.clone_from_slice(&self.0[45..]);
                Ok(public_key)
            }
            ExtendedKeyType::Private => {
                let secp = Secp256k1::signing_only();
                let secp_secret_key = SecretKey::from_slice(&secp, &self.0[46..])?;
                let secp_public_key = PublicKey::from_secret_key(&secp, &secp_secret_key);
                Ok(secp_public_key.serialize())
            }
        }
    }

    /// Gets the private key if this is an extended private key
    pub fn private_key(&self) -> Result<[u8; 32]> {
        if self.key_type()? == ExtendedKeyType::Private {
            let mut private_key = [0; 32];
            private_key.clone_from_slice(&self.0[46..]);
            Ok(private_key)
        } else {
            let msg = "Cannot get private key of public extended key";
            Err(Error::BadData(msg.to_string()))
        }
    }

    /// Gets the fingerprint of the public key hash
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let mut fingerprint = [0; 4];
        let public_key_hash = hash160(&self.public_key()?);
        fingerprint.clone_from_slice(&public_key_hash.0[..4]);
        Ok(fingerprint)
    }

    /// Gets the extenced public key for this key
    pub fn extended_public_key(&self) -> Result<ExtendedKey> {
        match self.key_type()? {
            ExtendedKeyType::Public => Ok(self.clone()),
            ExtendedKeyType::Private => {
                let private_key = &self.0[46..];
                let secp = Secp256k1::signing_only();
                let secp_secret_key = SecretKey::from_slice(&secp, &private_key)?;
                let secp_public_key = PublicKey::from_secret_key(&secp, &secp_secret_key);
                let public_key = secp_public_key.serialize();

                ExtendedKey::new_public_key(
                    self.network()?,
                    self.depth(),
                    &self.0[5..9],
                    self.index(),
                    &self.0[13..45],
                    &public_key,
                )
            }
        }
    }

    /// Derives an extended child private key from an extended parent private key
    pub fn derive_private_key(&self, index: u32) -> Result<ExtendedKey> {
        if self.key_type()? == ExtendedKeyType::Public {
            let msg = "Cannot derive private key from public key";
            return Err(Error::BadData(msg.to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            let msg = "Cannot derive extended key. Depth already at max.";
            return Err(Error::BadData(msg.to_string()));
        }

        let secp = Secp256k1::signing_only();
        let private_key = &self.0[46..];
        let secp_par_secret_key = SecretKey::from_slice(&secp, &private_key)?;
        let chain_code = &self.0[13..45];
        let key = hmac::SigningKey::new(&SHA512, chain_code);

        let hmac = if index >= HARDENED_KEY {
            let mut v = Vec::<u8>::with_capacity(37);
            v.push(0);
            v.extend_from_slice(&private_key);
            v.write_u32::<BigEndian>(index)?;
            hmac::sign(&key, &v)
        } else {
            let mut v = Vec::<u8>::with_capacity(37);
            let secp_public_key = PublicKey::from_secret_key(&secp, &secp_par_secret_key);
            let public_key = secp_public_key.serialize();
            v.extend_from_slice(&public_key);
            v.write_u32::<BigEndian>(index)?;
            hmac::sign(&key, &v)
        };

        if hmac.as_ref().len() != 64 {
            return Err(Error::IllegalState("HMAC invalid length".to_string()));
        }

        if !is_private_key_valid(&hmac.as_ref()[..32]) {
            let msg = "Invalid key. Try next index.".to_string();
            return Err(Error::IllegalState(msg));
        }

        let mut secp_child_secret_key = SecretKey::from_slice(&secp, &hmac.as_ref()[..32])?;
        secp_child_secret_key.add_assign(&secp, &secp_par_secret_key)?;

        let child_chain_code = &hmac.as_ref()[32..];
        let fingerprint = self.fingerprint()?;
        let child_private_key =
            unsafe { slice::from_raw_parts(secp_child_secret_key.as_ptr(), 32) };

        ExtendedKey::new_private_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            child_private_key,
        )
    }

    /// Derives an extended child public key from an extended parent public key
    pub fn derive_public_key(&self, index: u32) -> Result<ExtendedKey> {
        if index >= HARDENED_KEY {
            return Err(Error::BadArgument("i cannot be hardened".to_string()));
        }
        let network = self.network()?;
        if self.depth() == 255 {
            let msg = "Cannot derive extended key. Depth already at max.";
            return Err(Error::BadData(msg.to_string()));
        }

        let chain_code = &self.0[13..45];
        let key = hmac::SigningKey::new(&SHA512, chain_code);
        let mut v = Vec::<u8>::with_capacity(65);
        let public_key = self.public_key()?;
        v.extend_from_slice(&public_key);
        v.write_u32::<BigEndian>(index)?;
        let hmac = hmac::sign(&key, &v);

        if hmac.as_ref().len() != 64 {
            return Err(Error::IllegalState("HMAC invalid length".to_string()));
        }

        if !is_private_key_valid(&hmac.as_ref()[..32]) {
            let msg = "Invalid key. Try next index.".to_string();
            return Err(Error::IllegalState(msg));
        }

        let secp = Secp256k1::signing_only();
        let child_offset = SecretKey::from_slice(&secp, &hmac.as_ref()[..32])?;
        let child_offset = PublicKey::from_secret_key(&secp, &child_offset);
        let secp_par_public_key = PublicKey::from_slice(&secp, &public_key)?;
        let secp_child_public_key = secp_par_public_key.combine(&secp, &child_offset)?;
        let child_public_key = secp_child_public_key.serialize();

        let child_chain_code = &hmac.as_ref()[32..];
        let fingerprint = self.fingerprint()?;

        ExtendedKey::new_public_key(
            network,
            self.depth() + 1,
            &fingerprint,
            index,
            child_chain_code,
            &child_public_key,
        )
    }

    /// Encodes an extended key into a string
    pub fn encode(&self) -> String {
        let checksum = sha256d(&self.0);
        let mut v = Vec::with_capacity(82);
        v.extend_from_slice(&self.0);
        v.extend_from_slice(&checksum.0[..4]);
        v.to_base58()
    }

    /// Decodes an extended key from a string
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = s.from_base58()?;
        let checksum = sha256d(&v[..78]);
        if checksum.0[..4] != v[78..] {
            return Err(Error::BadArgument("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.clone_from_slice(&v[..78]);
        Ok(extended_key)
    }
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut k = ExtendedKey([0; 78]);
        reader.read(&mut k.0)?;
        Ok(k)
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write(&self.0)?;
        Ok(())
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl PartialEq for ExtendedKey {
    fn eq(&self, other: &ExtendedKey) -> bool {
        self.0.to_vec() == other.0.to_vec()
    }
}

impl Eq for ExtendedKey {}

/// Derives a key using the BIP-32 and BIP-44 shortened key notation
pub fn derive_extended_key(master: &ExtendedKey, path: &str) -> Result<ExtendedKey> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut key_type = ExtendedKeyType::Public;

    if parts[0] == "m" {
        if master.key_type()? == ExtendedKeyType::Public {
            let msg = "Cannot derive private key from public master";
            return Err(Error::BadArgument(msg.to_string()));
        }
        key_type = ExtendedKeyType::Private;
    } else if parts[0] != "M" {
        let msg = "Path must start with m or M";
        return Err(Error::BadArgument(msg.to_string()));
    }

    let mut key = master.clone();

    for part in parts[1..].iter() {
        if part.len() == 0 {
            let msg = "Empty part";
            return Err(Error::BadArgument(msg.to_string()));
        }

        let index = if part.ends_with("'") || part.ends_with("h") || part.ends_with("H") {
            let index: u32 = part
                .trim_end_matches("'")
                .trim_end_matches("h")
                .trim_end_matches("H")
                .parse()?;
            if index >= HARDENED_KEY {
                let msg = "Key index is already hardened";
                return Err(Error::BadArgument(msg.to_string()));
            }
            index + HARDENED_KEY
        } else {
            part.parse()?
        };

        key = match key_type {
            ExtendedKeyType::Public => key.derive_public_key(index)?,
            ExtendedKeyType::Private => key.derive_private_key(index)?,
        };
    }

    Ok(key)
}

/// Checks that a private key is in valid SECP256K1 range
pub fn is_private_key_valid(key: &[u8]) -> bool {
    let mut is_below_order = false;
    if key.len() != 32 {
        return false;
    }
    for i in 0..32 {
        if key[i] < SECP256K1_CURVE_ORDER[i] {
            is_below_order = true;
            break;
        }
    }
    if !is_below_order {
        return false;
    }
    for i in 0..32 {
        if key[i] != 0 {
            return true;
        }
    }
    return false;
}
