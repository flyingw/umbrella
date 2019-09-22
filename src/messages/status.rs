use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::ctx::Ctx;
use crate::lil_rlp;
use std::io;
use std::io::{Read, Write};
use std::fmt;

const PACKET_USER: u8 = 0x10;
 const PACKET_STATUS: u8 = 0x00 + PACKET_USER;

pub struct Status {
    pub protocol_version: u128,
    pub network_id: u128,
    pub difficulty: u128,
    pub latest_hash: Vec<u8>,
    pub genesis: Vec<u8>,
}

impl Serializable<Status> for Status{
    fn read(reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Status> {
        let mut packet_id_buf: Vec<u8> = vec![0u8; 1];
        reader.read_exact(packet_id_buf.as_mut())?;
        let packet_id: u8 = packet_id_buf[0];
        if (packet_id == PACKET_STATUS) {
            let mut payload = Vec::new();
            reader.read_to_end(&mut payload)?;
            let packet: Vec<u8> = parity_snappy::decompress(&payload).unwrap();
            let mut iter = packet.iter();

            let _skip_size = lil_rlp::list_size(&mut iter).unwrap();
            let protocol_version: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let network_id: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let difficulty: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let latest_hash = lil_rlp::get_str(&mut iter).unwrap();
            let genesis = lil_rlp::get_str(&mut iter).unwrap();

            // let latest_hash_size: usize = lil_rlp::list_size(&mut iter).unwrap();
            // let latest_hash_size: Vec<u8> = iter.take(latest_hash_size).map(|x| *x).collect();
            
            // use rlp::Rlp;
            // use ethereum_types::{U256};
            // let rlp: Rlp = Rlp::new(&packet);
            // let protocol_version: u8 = rlp.val_at(0).unwrap();
            // let network_id: u64 = rlp.val_at(1).unwrap();
            // let difficulty: U256 = rlp.val_at(2).unwrap();
            // let latest_hash: Vec<u8> = rlp.val_at(3).unwrap();
            // let genesis: Vec<u8> = rlp.val_at(4).unwrap();

            // println!("1={}, {}", protocol_version, protocol_version_1);
            // println!("2={}, {}", network_id, network_id_1);
            // println!("3={}, {}", difficulty, difficulty_1);
            // println!("4=\n{:?},\n{:?}", latest_hash, latest_hash_1);
            // println!("5=\n{:?}\n{:?}", genesis, genesis_1);

            Ok(Status{
                protocol_version: protocol_version,
                network_id: network_id,
                difficulty: difficulty,
                latest_hash: latest_hash,
                genesis: genesis,
            })
        } else {
            Err(Error::ScriptError(format!("not a Status message, id={}", packet_id)))
        }
    }

    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        panic!("Status write");
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Status")
            .finish()
    }
}
