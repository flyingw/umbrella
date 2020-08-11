use crate::hash256::Hash256;
use crate::result::{Error, Result};

/// Network type
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
    Ethereum = 3,
    BsvMainnet = 4,
    BsvRegtest = 5,
}

impl Network {
    /// Converts an integer to a network type
    pub fn from_u8(x: u8) -> Result<Network> {
        match x {
            x if x == Network::Mainnet as u8 => Ok(Network::Mainnet),
            x if x == Network::Testnet as u8 => Ok(Network::Testnet),
            x if x == Network::Regtest as u8 => Ok(Network::Regtest),
            x if x == Network::Ethereum as u8 => Ok(Network::Ethereum),
            x if x == Network::BsvMainnet as u8 => Ok(Network::BsvMainnet),
            x if x == Network::BsvRegtest as u8 => Ok(Network::BsvRegtest),
            _ => {
                let msg = format!("Unknown network type: {}", x);
                Err(Error::BadArgument(msg))
            }
        }
    }

    /// Returns the default TCP port
    pub fn port(&self) -> u16 {
        match self {
            Network::Mainnet    =>  8333,
            Network::Testnet    => 18333,
            Network::Regtest    => 18444,
            Network::Ethereum   => 30301,
            Network::BsvMainnet =>  8333, // guess. check it
            Network::BsvRegtest => 18444,
        }
    }

    /// Returns the magic bytes for the message headers
    pub fn magic(&self) -> [u8; 4] {
        match self {
            Network::Mainnet    => [0xe3, 0xe1, 0xf3, 0xe8],
            Network::Testnet    => [0xf4, 0xe5, 0xf3, 0xf4],
            Network::Regtest    => [0xda, 0xb5, 0xbf, 0xfa],
            Network::Ethereum   => [0xc2, 0x80, 0x80, 0x00],
            Network::BsvMainnet => [0xe3, 0xe1, 0xf3, 0xe8], // guess. check it
            Network::BsvRegtest => [0xda, 0xb5, 0xbf, 0xfa],
            // Network::BtcRegtest => [0xfa, 0xbf, 0xb5, 0xda], // for some reason only reverted order works
        }
    }

    /// Returns the genesis block hash
    pub fn genesis_hash(&self) -> Hash256 {
        match self {
            Network::Mainnet => {
                Hash256::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                    .unwrap()
            }
            Network::Testnet => {
                Hash256::decode("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
                    .unwrap()
            }
            Network::Regtest => {
                Hash256::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                    .unwrap()
            }
            Network::Ethereum => {
                Hash256::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                    .unwrap()
            }
            Network::BsvMainnet => {
                Hash256::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") // guess. check it
                    .unwrap()
            }
            Network::BsvRegtest => {
                Hash256::decode("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                    .unwrap()
            }
        }
    }

    /// Returns the ascii prefix for CashAddr addresses
    pub fn cashaddr_prefix(&self) -> String {
        match self {
            Network::Mainnet => "bitcoincash".to_string(),
            Network::Testnet => "bchtest".to_string(),
            Network::Regtest => "bchreg".to_string(),
            Network::Ethereum => "eth".to_string(),
            Network::BsvMainnet => "bsv".to_string(),
            Network::BsvRegtest => "bsvreg".to_string(),
        }
    }

    /// Returns the version byte flag for P2PKH-type legacy addresses
    pub fn legacyaddr_pubkeyhash_flag(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6f,
            Network::Regtest => 0x00,
            Network::Ethereum => 0x00,
            Network::BsvMainnet => 0x00,
            Network::BsvRegtest => 0x6f, // not legacy. is using for bsv
        }
    }

    /// Returns the version byte flag for P2SH-type legacy addresses
    pub fn legacyaddr_script_flag(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet => 0xc4,
            Network::Regtest => 0x00,
            Network::Ethereum => 0x00,
            Network::BsvMainnet => 0x00, // not used for bsv
            Network::BsvRegtest => 0x00, // not used for bsv
        }
    }

    /// Returns a list of DNS seeds for finding initial nodes
    pub fn seeds(&self) -> Vec<String> {
        match self {
            Network::Mainnet => vec![
                "seed.bitcoinabc.org".to_string(),
                "seed-abc.bitcoinforks.org".to_string(),
                "btccash-seeder.bitcoinunlimited.info".to_string(),
                "seed.bitprim.org".to_string(),
                "seed.deadalnix.me".to_string(),
                "seeder.criptolayer.net".to_string(),
            ],
            Network::Testnet => vec![
                "testnet-seed.bitcoinabc.org".to_string(),
                "testnet-seed-abc.bitcoinforks.org".to_string(),
                "testnet-seed.bitprim.org".to_string(),
                "testnet-seed.deadalnix.me".to_string(),
                "testnet-seeder.criptolayer.net".to_string(),
            ],
            // seed nodes which actually can return the ips of real nodes.
            // but its not implemented yet, so just return name for localhost here
            // and add some parsing for enode:// format.
            Network::Regtest    => vec!["localhost".to_string()],
            Network::Ethereum   => vec!["localhost".to_string()],
            Network::BsvMainnet => vec!["localhost".to_string()], // define correct ones
            Network::BsvRegtest => vec!["localhost".to_string()],
        }
    }
}
