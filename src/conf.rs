use structopt::StructOpt;
use std::str::FromStr;
use crate::hash256::Hash256;
use crate::network::Network;

#[derive(StructOpt,Debug)]
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

#[derive(Debug)]
pub struct HexData(Vec<u8>);
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
    /// Amount to pay for data storeage.
    /// 
    pub dust_amount: f64,
    
    #[structopt(short,long="data")]
    /// Data to be incuded in output.
    /// 
    pub data: HexData,
}

#[derive(StructOpt, Debug)]
#[structopt(name="umbrella", raw(setting = "structopt::clap::AppSettings::ColoredHelp"))]
/// Make a note on transaction.
/// 
/// Sender wallet is a pair of address and secret.
/// We don't create it so it should exist.
/// 
/// Recipient address is encoded (base58 160-bit hash) form of hash of their public key.
/// 
/// Address encode the network, so we need a network parameter too.
/// 
pub struct Opt {
    #[structopt(flatten)]
    pub sender: Wallet,

    #[structopt(flatten)]
    pub data: Data,

    #[structopt(short, long, default_value="parse(\"BCH-regtest\")")]
    /// Network for with the address is encoded
    /// 
    /// Supported networks: "BCH", "BCH-test", "BCH-reg"
    pub network: Network,

    /// Verbose mode (-v, -vv, -vvv, -vvvv)
    #[structopt(short="v", long="verbose", parse(from_occurrences))]
    pub verbose:usize,
    
    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool,
}
