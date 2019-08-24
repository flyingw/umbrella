extern crate ethcore_network_devp2p;

use std::str::FromStr;
use ethcore_network_devp2p::node_table::{Node};

fn main() {
	let enode = "enode://05e7558bf83a49d76fdf8544d06edd4c95146167175a3d8847a652125d95091493b4f71bf1ffcc60153ce8eddc04cf34e18e8d6a19a69cc2bdab4dbd159a7859@127.0.0.1:30301";
	let node: Node = FromStr::from_str(enode).unwrap();
  println!("{:?}", node.endpoint.address);
}
