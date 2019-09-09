use structopt::StructOpt;
use std::str::FromStr;
use crate::hash256::Hash256;

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
}

impl Network {
    pub fn network(&self) -> crate::network::Network {
        match *self {
            Network::BCH{..}    => crate::network::Network::Mainnet,
            Network::BCHTest{..}=> crate::network::Network::Testnet,
            Network::BCHReg{..} => crate::network::Network::Regtest,
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
    pub fn sender(&self) -> &Wallet {
        match &self.network {
            Network::BCH{sender, ..}    => sender,
            Network::BCHTest{sender, ..}=> sender,
            Network::BCHReg{sender, ..} => sender,
        }
    }
    pub fn data(&self) -> &Data{
        match &self.network {
            Network::BCH{sender:_, data}    => data,
            Network::BCHTest{sender:_, data}=> data,
            Network::BCHReg{sender:_, data} => data,
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