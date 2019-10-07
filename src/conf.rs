use structopt::StructOpt;
use std::str::FromStr;
use crate::hash256::Hash256;
use secp256k1::{ecdh, Secp256k1, key::{PublicKey, SecretKey}};

#[derive(StructOpt,Debug)]
/// Sender information.
pub struct Wallet {
    #[structopt(long)]
    /// Public address of sender to be used as input.
    ///
    pub in_address: String,

    #[structopt(long)]
    /// input UTXO amount
    ///
    pub in_amount: f64,

    #[structopt(long, parse(try_from_str="Hash256::decode"))]
    /// OutPoint transaction id.
    ///
    pub outpoint_hash: Hash256,

    #[structopt(long)]
    /// OutPoint vout index.
    ///
    pub outpoint_index: u32,

    #[structopt(long)]
    /// Private key to sign sender input. 
    ///
    /// Supported format: WIF (Wallet Import Format) - base56check encoded string.
    ///
    /// > bitcoin-cli -regtest dumpprivkey "address"
    ///
    pub secret: String,

    #[structopt(long)]
    /// Public addrss to be used as output for change.
    ///
    /// > bitcoin-cli -regtest getnewaddress
    ///
    pub out_address: String,

    #[structopt(long)]
    /// Change from input transaction. 
    /// Amout that should be returned to new sender address and don't burned or spent for writing data.
    ///
    pub change: f64,
}

#[derive(StructOpt,Debug)]
/// Eth node info
pub struct EthWallet {
    #[structopt(long)]
    /// Node public key
    ///
    pub pub_key: HexData,

    #[structopt(long, required_unless="crypto")]
    /// Secret key. Having this key drastically improve the performance.
    ///
    pub secret: Option<String>,

    #[structopt(long, required_unless="secret")]
    /// Crypto part of privkey file.
    /// Generating private key on ETH will take a lot of time (for undiscovered yet reason),
    /// so if you have it from another sources just provide the secret key
    ///
    pub crypto: Option<String>,

    #[structopt(long)]
    /// Secret key password
    ///
    pub password: String,

    #[structopt(long)]
    /// Public addrss to be used as output.
    ///
    pub out_address: String,

    /// Transfered value
    ///
    #[structopt(long)]
    pub value: u128, 

    /// Gas paid up front for transaction execution
    ///
    #[structopt(long, default_value="21000")]
    pub gas: u128,

    /// Gas price
    ///
    #[structopt(long, default_value="1000000000")]
    pub gas_price: u128,
}

/// Initial encryption configuration
#[derive(Clone)]
pub struct EncOpt {
    pub node_public: PublicKey,
    pub node_secret: SecretKey, 
    pub msg_secret: SecretKey,
    pub enc_version: Vec<u8>,
    pub nonce: Hash256,
}

use crate::keys::{public_to_slice, sign, slice_to_public};
use crate::messages::{Message, NodeKey, Version, PROTOCOL_VERSION, NODE_NONE};

pub trait Sender {
    fn change(&self) -> f64 {0.0}
    fn secret(&self) -> Option<String> {None}
    fn crypto(&self) -> Option<String> {None}
    fn pub_key(&self) -> Vec<u8> {vec![]}
    fn password(&self) -> String {String::new()}
    fn in_amount(&self) -> f64 {0.0}
    fn in_address(&self) -> String {String::new()}
    fn out_address(&self) -> String;
    fn outpoint_hash(&self) -> Hash256 {Hash256::default()}
    fn outpoint_index(&self) -> u32 {0}
    fn gas(&self)       -> u128 {0}
    fn gas_price(&self) -> u128 {0}
    fn value(&self)     -> u128 {0}
    fn encryption_conf(&self) -> Option<EncOpt> { None }
    fn version(&self, cfg: &Option<EncOpt>) -> Message; 
}

use std::time::UNIX_EPOCH;
use crate::util::secs_since;

impl Sender for Wallet {
    fn in_address(&self) -> String {return self.in_address.clone();}
    fn out_address(&self) -> String {return self.out_address.clone();}
    fn outpoint_hash(&self) -> Hash256 {return self.outpoint_hash;}
    fn outpoint_index(&self) -> u32 {return self.outpoint_index;}
    fn change(&self) -> f64 {return self.change;}
    fn in_amount(&self) -> f64 {return self.in_amount;}
    fn secret(&self) -> Option<String> {return Some(self.secret.clone());}

    fn version(&self, _cfg: &Option<EncOpt>) -> Message {
        let version = Version {
            version: PROTOCOL_VERSION,
            services: NODE_NONE, 
            timestamp: secs_since(UNIX_EPOCH) as i64,
            user_agent: "umbrella".to_string(),
            ..Default::default()
        };

        Message::Version(version)
    }
}

impl Sender for EthWallet {
    fn pub_key(&self)     -> Vec<u8> {self.pub_key.0.clone()}
    fn secret(&self)      -> Option<String> {self.secret.clone()}
    fn crypto(&self)      -> Option<String> {self.crypto.clone()}
    fn password(&self)    -> String {self.password.clone()}
    fn out_address(&self) -> String {self.out_address.clone()}
    
    fn gas(&self)   -> u128 {self.gas}
    fn value(&self) -> u128 {self.value}
    fn gas_price(&self) -> u128 {self.gas_price}

    fn encryption_conf(&self) -> Option<EncOpt> {
        let mut rng = rand::thread_rng();
        let pub_key:PublicKey = slice_to_public(&self.pub_key.0).unwrap();

        let nonce: Hash256 = Hash256::random();
        let secp = Secp256k1::new();
        let (node_secret, node_public) = secp.generate_keypair(&mut rng);
        let (msg, msg_secret) = encrypt_node_version(pub_key, node_public, node_secret, nonce);

        Some(EncOpt {
            node_public: node_public,
            node_secret: node_secret, 
            msg_secret: msg_secret,
            enc_version: msg,
            nonce: nonce,  
        })
    }

    fn version(&self, cfg: &Option<EncOpt>) -> Message {
        let version = NodeKey {
            version: cfg.as_ref().unwrap().enc_version.clone(),
        };
        Message::NodeKey(version)
    }
}

use tiny_keccak::Keccak;
use crate::ecies;
/// Probably a part of version message with encryption support
/// 
fn encrypt_node_version(pub_key:PublicKey
                      , node_public:PublicKey
                      , node_secret:SecretKey
                      , nonce: Hash256) -> (Vec<u8>, SecretKey) {
    let mut rng = rand::thread_rng();
    let secp = Secp256k1::new();

    let mut version = [0u8;194]; //sig + public + 2*h256 + 1

    version[193] = 0x0;

    let (sig, rest) = version.split_at_mut(65);
    let (version_pub, rest) = rest.split_at_mut(32);
    let (node_pub, rest) = rest.split_at_mut(64);
    let (data_nonce, _) = rest.split_at_mut(32);
    
    let (sec1, pub1) = secp.generate_keypair(&mut rng);
    let pub1 = public_to_slice(&pub1);
    let sec1 =  SecretKey::from_slice(&sec1[..32]).unwrap();

    let shr = ecdh::SharedSecret::new_with_hash(&pub_key, &node_secret, &mut hash);
    let xor = Hash256::from_slice(&shr[..]) ^ nonce;

    //signature
    sig.copy_from_slice(&sign(&sec1, &xor));
    Keccak::keccak256(&pub1, version_pub);
    node_pub.copy_from_slice(&public_to_slice(&node_public));
    data_nonce.copy_from_slice(nonce.as_bytes());

    (ecies::encrypt(&pub_key, &[], &version).unwrap(), sec1)
}

fn hash(output: &mut [u8], x: &[u8], _y: &[u8]) -> i32 {
    output.copy_from_slice(x);
    1
}

#[derive(Debug, Clone)]
pub struct HexData(Vec<u8>);
impl HexData {
    #[inline]
    pub fn as_vec(&self) -> Vec<u8> {self.0.clone()}
}
impl FromStr for HexData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { hex::decode(s).map(HexData) }
}

#[derive(StructOpt, Debug)]
pub struct Data {
    #[structopt(long)]
    /// Public address to pay for data storage.
    /// 
    /// > bitcoin-cli -regtest getnewaddress
    /// 
    pub dust_address: String,
    
    #[structopt(long, default_value="0.0001")]
    /// Amount to pay for data storage.
    /// 
    pub dust_amount: f64,
    
    #[structopt(long)]
    /// Data to be incuded in output.
    /// 
    pub data: HexData,
}

#[derive(StructOpt, Debug)]
/// Network configuration.
/// 
pub enum Network {
    #[structopt(name="bch", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    /// Operate on Bitcoin Cash main network
    BCH{
        #[structopt(flatten)] sender: Wallet,
        #[structopt(flatten)] data: Data,
    },
    #[structopt(name="bch-test", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    /// Operate on Bitcoin Cash test network
    BCHTest{
        #[structopt(flatten)] sender: Wallet,
        #[structopt(flatten)] data: Data,
    },
    #[structopt(name="bch-reg", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    /// Operate on Bitcoin Cash Regtest network
    BCHReg{
        #[structopt(flatten)] sender: Wallet,
        #[structopt(flatten)] data: Data,
    },
    #[structopt(name="eth", raw(setting="structopt::clap::AppSettings::ColoredHelp"))]
    /// Operate on Ethereum network
    Eth{
        #[structopt(flatten)] sender: EthWallet,
        //find how to remove that shit
        #[structopt(flatten)] data: Data,
    },
    #[structopt(name="btc-reg", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
    /// Operate on Bitcoin Core Regtest network
    BTCReg{
        #[structopt(flatten)] sender: Wallet,
        #[structopt(flatten)] data: Data,
    },
}

impl Network {
    pub fn network(&self) -> crate::network::Network {
        match *self {
            Network::BCH{..}    => crate::network::Network::Mainnet,
            Network::BCHTest{..}=> crate::network::Network::Testnet,
            Network::BCHReg{..} => crate::network::Network::Regtest,
            Network::Eth{..}    => crate::network::Network::Ethereum,
            Network::BTCReg{..} => crate::network::Network::BtcRegtest,
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name="umbrella", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
/// Make a note on transaction within a network selected by <SUBCOMMAND>.
/// 
/// Run `help <SUBCOMMAND>` for [OPTIONS] description.
pub struct Opt {
    #[structopt(subcommand)]
    pub network: Network,

    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool,
}

impl Opt {
    pub fn sender(&self) -> &dyn Sender {
        match &self.network {
            Network::BCH{sender, ..}    => sender,
            Network::BCHTest{sender, ..}=> sender,
            Network::BCHReg{sender, ..} => sender,
            Network::Eth{sender, ..}    => sender,
            Network::BTCReg{sender, ..} => sender,
        }
    }
    pub fn data(&self) -> &Data{
        
        match &self.network {
            Network::BCH{sender:_, data}    => data,
            Network::BCHTest{sender:_, data}=> data,
            Network::BCHReg{sender:_, data} => data,
            Network::Eth{sender:_, data}    => data,
            Network::BTCReg{sender:_, data} => data,
        }
    }
}

#[cfg(test)]
mod tests{
    #[test] fn help_network() {
        use super::*;
        Opt::from_iter(&["umbrella", "help", "bch-reg"]);
    }
}