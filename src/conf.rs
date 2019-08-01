use structopt::StructOpt;
use std::path::PathBuf;

#[derive(StructOpt,Debug)]
struct Wallet {
    #[structopt(long, default_value="mrvz6oz4YGxsHk3VggP8aQCFzMxCLdtmzX")]
    /// Public address of sender wallet.
    address: String,
    #[structopt(long, default_value="92ctZsdvgQ2eRPjHDtjgQ6Y7oogLKoDMXCdnqmgAd62s5MjrHvb")]
    /// Private key of sender wallet. Can also be imported from file.
    secret: String,
}

#[derive(StructOpt, Debug)]
struct Miner {
    #[structopt(long)]
    /// Recipients.
    recipients: Vec<String>,
    #[structopt(long, parse(from_os_str))]
    /// Optional address path.
    path: Option<PathBuf>,
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
/// Note: Give money back to mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt.
pub struct Opt {
    #[structopt(flatten)]
    sender: Wallet,
    #[structopt(flatten)]
    miner: Miner,
    #[structopt(long, default_value="testnet")]
    /// Network for with the address is encoded.
    network:String,
}
