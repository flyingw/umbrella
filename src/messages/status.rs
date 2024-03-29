use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::ctx::Ctx;
use crate::lil_rlp;
use super::message::Payload;
use std::io;
use std::io::{Read, Write};
use std::fmt;
use crate::hash128::Hash128;
use aes::Aes256;
use block_modes::{BlockMode, Ecb, block_padding::{ZeroPadding}};
use aes_ctr::stream_cipher::SyncStreamCipher;
use snap;

const PACKET_USER: u8 = 0x10;
const PACKET_STATUS: u8 = 0x00 + PACKET_USER;
const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

#[derive(Clone)]
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
        if packet_id == PACKET_STATUS {
            let mut payload = Vec::new();
            reader.read_to_end(&mut payload)?;
            let mut dec = snap::raw::Decoder::new();
            let packet: Vec<u8> = dec.decompress_vec(&payload).unwrap();
            let mut iter = packet.iter();

            let _skip_size = lil_rlp::list_size(&mut iter).unwrap();
            let protocol_version: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let network_id: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let difficulty: u128 = lil_rlp::get_num(&mut iter).unwrap();
            let latest_hash = lil_rlp::get_str(&mut iter).unwrap();
            let genesis = lil_rlp::get_str(&mut iter).unwrap();

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
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.protocol_version);
        lil_rlp::put_num(&mut buf, self.network_id);
        lil_rlp::put_num(&mut buf, self.difficulty);
        lil_rlp::put_str(&mut buf, &self.latest_hash);
        lil_rlp::put_str(&mut buf, &self.genesis);
        let data: Vec<u8> = lil_rlp::as_list(&buf);
        let mut enc = snap::raw::Encoder::new();
        let data_compressed = enc.compress_vec(&data).unwrap();

        let len = data_compressed.len() + 1;
        if len > MAX_PAYLOAD_SIZE {
			panic!("status max payload exceeded {}", len);
		}

        let padding = (16 - (len % 16)) % 16;
        let mut packet: Vec<u8> = vec![0u8; len + padding + 16];
        packet[0] = PACKET_STATUS;
        packet[1..len].copy_from_slice(&data_compressed);

        Ctx::encoder(ctx).try_apply_keystream(&mut packet[..len]).unwrap();
        if padding != 0 {
            Ctx::encoder(ctx).try_apply_keystream(&mut packet[len..(len + padding)]).unwrap();
		}
        Ctx::update_remote_mac(ctx, &packet[..(len + padding)]);
        writer.write_all(&packet[..(len + padding)])?;

        let mut prev = Hash128::default();
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());

		let mut enc = Hash128::default();
		let _ = &mut enc[..].copy_from_slice(prev.as_bytes());

        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).expect("failed to aes ecb 1");
	    let enc_mut = enc.as_bytes_mut();
		mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();

        Ctx::update_remote_mac(ctx, (enc ^ prev).as_bytes());

        let mut b = [0;16];
        Ctx::get_remote_mac(ctx, &mut b);
        writer.write_all(&b)
    }
}

impl Payload<Status> for Status {
    fn size(&self) -> usize {
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.protocol_version);
        lil_rlp::put_num(&mut buf, self.network_id);
        lil_rlp::put_num(&mut buf, self.difficulty);
        lil_rlp::put_str(&mut buf, &self.latest_hash);
        lil_rlp::put_str(&mut buf, &self.genesis);
        let data: Vec<u8> = lil_rlp::as_list(&buf);
        let mut enc = snap::raw::Encoder::new();
        let data_compressed = enc.compress_vec(&data).unwrap();

        let len = data_compressed.len() + 1;
        len
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Status").finish()
    }
}
