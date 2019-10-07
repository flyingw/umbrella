use crate::result::Result;
use std::fmt;
use super::message::Payload;
use crate::serdes::Serializable;
use std::io;
use std::io::{Read, Write};
use crate::ctx::Ctx;
use block_modes::{BlockMode, Ecb, block_padding::{ZeroPadding}};
use aes_ctr::stream_cipher::SyncStreamCipher;
use crate::hash128::Hash128;
use crate::hash256::Hash256;
use crate::keys::{Address, Signature, sign};
use secp256k1::key::{SecretKey};
use aes::Aes256;
use crate::lil_rlp;
use tiny_keccak::Keccak;
use snap;

const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

#[derive(Default)]
pub struct Tx2 {
    /// Nonce.
	pub nonce: u128,
	/// Gas price.
	pub gas_price: u128,
	/// Gas paid up front for transaction execution.
	pub gas: u128,
	/// Call address
	pub call: Address,
	/// Transfered value.
	pub value: u128,
	/// Transaction data.
	pub data: Vec<u8>,
	/// The V field of the signature; the LS bit described which half of the curve our point falls
	/// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
	pub v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	pub r: Hash256,
	/// The S field of the signature; helps describe the point on the curve.
	pub s: Hash256,
}

impl Tx2 {

    pub fn hash(&mut self) -> Hash256 {
        let mut result = [0u8; 32];
        
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.nonce);
        lil_rlp::put_num(&mut buf, self.gas_price);
        lil_rlp::put_num(&mut buf, self.gas);
        lil_rlp::put_str(&mut buf, &self.call.to_vec());
        lil_rlp::put_num(&mut buf, self.value);
        lil_rlp::put_str(&mut buf, &self.data);
        lil_rlp::put_num(&mut buf, self.v.into());
        lil_rlp::put_str(&mut buf, &self.r.as_bytes().to_vec());
        lil_rlp::put_str(&mut buf, &self.s.as_bytes().to_vec());
        
        Keccak::keccak256(&lil_rlp::as_list(&buf), &mut result);
		Hash256(result)
    }

	pub fn is_unsigned(&self) -> bool {
        !self.r.as_bytes().contains(&0) &&
        !self.s.as_bytes().contains(&0)
	}

    pub fn unsigned_hash(&self, chain_id: Option<u64>) -> Hash256 {
        // this hash is unsigned
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.nonce);
        lil_rlp::put_num(&mut buf, self.gas_price);
        lil_rlp::put_num(&mut buf, self.gas);
        lil_rlp::put_str(&mut buf, &self.call.to_vec());
        lil_rlp::put_num(&mut buf, self.value);
        lil_rlp::put_str(&mut buf, &self.data);
        if let Some(n) = chain_id {
            lil_rlp::put_num(&mut buf, n.into());
			lil_rlp::put_num(&mut buf, 0u128);
			lil_rlp::put_num(&mut buf, 0u128);
        }
        let res = lil_rlp::as_list(&buf);
        let mut result = [0u8; 32];
	    Keccak::keccak256(&res, &mut result);
		Hash256(result)
	}

    pub fn standard_v(&self) -> u8 { signature::check_replay_protection(self.v) }

    pub fn signature(&self) -> Signature {
        let mut sig = [0u8; 65];
        sig[0..32].copy_from_slice(&self.r.as_bytes());
        sig[32..64].copy_from_slice(&self.s.as_bytes());
        sig[64] = self.standard_v();
        sig
	}

    pub fn chain_id(&self) -> Option<u64> {
		match self.v {
			v if self.is_unsigned() => Some(v),
			v if v >= 35 => Some((v - 35) / 2),
			_ => None,
		}
	}

    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
		v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
	}

    pub fn sign(mut self, secret: &SecretKey, chain_id: Option<u64>) -> Self {
        let hash256 = self.unsigned_hash(chain_id);
		let sig = sign(secret, &hash256);
        
        let r: &[u8] = &sig[0..32];
        let s: &[u8] = &sig[32..64];
        self.r = Hash256::from_slice(r);
        self.s = Hash256::from_slice(s);
        self.v = Tx2::add_chain_replay_protection(sig[64] as u64, chain_id);

        self
	}
}


// Replay protection logic for v part of transaction's signature
pub mod signature {
	/// Returns refined v
	/// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
	pub fn check_replay_protection(v: u64) -> u8 {
		match v {
			v if v == 27 => 0,
			v if v == 28 => 1,
			v if v >= 35 => ((v - 1) % 2) as u8,
			_ => 4
		}
	}
}

const PACKET_USER: u8 = 0x10;
const PACKET_TRANSACTIONS: u8 = 0x02 + PACKET_USER;

impl Serializable<Tx2> for Tx2 {
    fn read(_reader: &mut dyn Read, _ctx: &mut dyn Ctx) -> Result<Tx2> {
        panic!("we've never read transactions");
    }
    fn write(&self, writer: &mut dyn Write, ctx: &mut dyn Ctx) -> io::Result<()> {
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.nonce);
        lil_rlp::put_num(&mut buf, self.gas_price);
        lil_rlp::put_num(&mut buf, self.gas);
        lil_rlp::put_str(&mut buf, &self.call.to_vec());
        lil_rlp::put_num(&mut buf, self.value);
        lil_rlp::put_str(&mut buf, &self.data);
        lil_rlp::put_num(&mut buf, self.v.into());
        lil_rlp::put_str(&mut buf, &self.r.as_bytes().to_vec());
        lil_rlp::put_str(&mut buf, &self.s.as_bytes().to_vec());
        let data = &lil_rlp::as_list(&lil_rlp::as_list(&buf));  

        let mut packet: Vec<u8> = vec![];
        lil_rlp::put_num(&mut packet, u128::from(PACKET_TRANSACTIONS));
        let mut enc = snap::Encoder::new();
        let compressed = enc.compress_vec(&data).unwrap();
        packet.extend(&compressed);
        
        let payload = &packet;
        
        // check some comments in module tests below
        let len = payload.len();
        if len > MAX_PAYLOAD_SIZE {
			panic!("OversizedPacket {}", len);
		}

        let padding = (16 - (len % 16)) % 16;
        let mut packet: Vec<u8> = vec![0u8; len + padding + 16];
        
		&mut packet[..len].copy_from_slice(&payload);
        Ctx::encoder(ctx).try_apply_keystream(&mut packet[..len]).unwrap();

		if padding != 0 {
            Ctx::encoder(ctx).try_apply_keystream(&mut packet[len..(len + padding)]).unwrap();
		}

        Ctx::update_remote_mac(ctx, &packet[..(len + padding)]);

        writer.write_all(&packet[..(len + padding)])?;

        let mut prev = Hash128::default();
        Ctx::get_remote_mac(ctx, prev.as_bytes_mut());

		let mut enc = Hash128::default();
		&mut enc[..].copy_from_slice(prev.as_bytes());

        let mac_encoder: Ecb<Aes256, ZeroPadding> = Ecb::new_var(&ctx.secret_key()[..], &[]).expect("failed to aes ecb 1");
	    let enc_mut = enc.as_bytes_mut();
		mac_encoder.encrypt(enc_mut, enc_mut.len()).unwrap();

        Ctx::update_remote_mac(ctx, (enc ^ prev).as_bytes());

        let mut b = [0;16];
        Ctx::get_remote_mac(ctx, &mut b);
        writer.write_all(&b)
    }

}

impl Payload<Tx2> for Tx2 {
    fn size(&self) -> usize {
        let mut buf: Vec<u8> = vec![];
        lil_rlp::put_num(&mut buf, self.nonce);
        lil_rlp::put_num(&mut buf, self.gas_price);
        lil_rlp::put_num(&mut buf, self.gas);
        lil_rlp::put_str(&mut buf, &self.call.to_vec());
        lil_rlp::put_num(&mut buf, self.value);
        lil_rlp::put_str(&mut buf, &self.data);
        lil_rlp::put_num(&mut buf, self.v.into());
        lil_rlp::put_str(&mut buf, &self.r.as_bytes().to_vec());
        lil_rlp::put_str(&mut buf, &self.s.as_bytes().to_vec());
        let data = &lil_rlp::as_list(&lil_rlp::as_list(&buf));
                                
        let mut packet: Vec<u8> = vec![];
        lil_rlp::put_num(&mut packet, u128::from(PACKET_TRANSACTIONS));
        let mut enc = snap::Encoder::new();
        let compressed = enc.compress_vec(data).unwrap();
        packet.extend(&compressed);

        let payload = &packet;
        debug!("Payload size: {:?}", &payload.len());
        payload.len()
    }
}

impl fmt::Debug for Tx2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Tx")
            .field("data:", &self.data)
            .finish()
    }
}
