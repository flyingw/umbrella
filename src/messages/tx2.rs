use ethereum_types::{H256, Address, U256, BigEndianHash};
use ethkey::{Public, Secret, Signature, recover, public_to_address};
use keccak_hash::{write_keccak};
use rlp::RlpStream;
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
use aes::Aes256;

const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

#[derive(Default)]
pub struct Tx2 {
    /// Nonce.
	pub nonce: U256,
	/// Gas price.
	pub gas_price: U256,
	/// Gas paid up front for transaction execution.
	pub gas: U256,
	/// Action, can be either call or contract create.
	pub call: Address,
	/// Transfered value.
	pub value: U256,
	/// Transaction data.
	pub data: Vec<u8>,
	/// The V field of the signature; the LS bit described which half of the curve our point falls
	/// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
	pub v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	pub r: U256,
	/// The S field of the signature; helps describe the point on the curve.
	pub s: U256,
	/// Hash of the transaction
	pub hash: H256,
    pub sender: Address,
	pub public: Option<Public>,
}

impl Tx2{
	pub fn is_unsigned(&self) -> bool {
		self.r.is_zero() && self.s.is_zero()
	}

    fn bytes(&self) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.begin_list(9);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
        s.append(&self.call);
		s.append(&self.value);
		s.append(&self.data);
		s.append(&self.v);
		s.append(&self.r);
		s.append(&self.s);
        s.drain()
    }

    pub fn hash(&self) -> H256 {
        self.hash
    }

    pub fn unsigned_hash(&self, chain_id: Option<u64>) -> H256 {
        // this hash is unsigned
		let mut stream = RlpStream::new();
        stream.begin_list(if chain_id.is_none() { 6 } else { 9 });
		stream.append(&self.nonce);
		stream.append(&self.gas_price);
		stream.append(&self.gas);
        stream.append(&self.call);
		stream.append(&self.value);
		stream.append(&self.data);
		if let Some(n) = chain_id {
			stream.append(&n);
			stream.append(&0u8);
			stream.append(&0u8);
		}

        let mut result = [0u8; 32];
        write_keccak(stream.as_raw(), &mut result);
		H256(result)
	}

    pub fn standard_v(&self) -> u8 { signature::check_replay_protection(self.v) }

    pub fn signature(&self) -> Signature {
		let r: H256 = BigEndianHash::from_uint(&self.r);
		let s: H256 = BigEndianHash::from_uint(&self.s);
		Signature::from_rsv(&r, &s, self.standard_v())
	}

    pub fn chain_id(&self) -> Option<u64> {
		match self.v {
			v if self.is_unsigned() => Some(v),
			v if v >= 35 => Some((v - 35) / 2),
			_ => None,
		}
	}

    pub fn recover_public(&self) -> Result<Public> {
		Ok(recover(&self.signature(), &self.unsigned_hash(self.chain_id())).unwrap() )// unsigned hash probably must be kept
	}

    pub fn sign(mut self, secret: &Secret, chain_id: Option<u64>) -> Self {
		let sig = ::ethkey::sign(secret, &self.unsigned_hash(chain_id))
			.expect("data is valid and context has signing capabilities; qed");
		
        self.r = sig.r().into();
        self.s = sig.s().into();
        self.v = signature::add_chain_replay_protection(sig.v() as u64, chain_id);
        self.hash = H256::zero();

        // compute hash, 
        let mut result = [0u8; 32];
        write_keccak(&*self.bytes(), &mut result);
		self.hash = H256(result);

        //
        let public = &self.recover_public().unwrap();
        self.sender = public_to_address(&public);
        self
	}
}


// Replay protection logic for v part of transaction's signature
pub mod signature {
	/// Adds chain id into v
	pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
		v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
	}

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
        let mut rlp = RlpStream::new_list(1);
        rlp.begin_list(9);
        rlp.append(&self.nonce);
        rlp.append(&self.gas_price);
        rlp.append(&self.gas);
        rlp.append(&self.call);
        rlp.append(&self.value);
        rlp.append(&self.data);
        rlp.append(&self.v);
        rlp.append(&self.r);
        rlp.append(&self.s);
                                
        let data = &rlp.out();
                                
        let mut rlp = RlpStream::new();
        rlp.append(&(u32::from(PACKET_TRANSACTIONS)));
        let mut compressed = Vec::new();
        let len = parity_snappy::compress_into(data, &mut compressed);
        let payload = &compressed[0..len];
        rlp.append_raw(payload, 1);

        let payload = &rlp.out();
        
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
        let mut rlp = RlpStream::new_list(1);
        rlp.begin_list(9);
        rlp.append(&self.nonce);
        rlp.append(&self.gas_price);
        rlp.append(&self.gas);
        rlp.append(&self.call);
        rlp.append(&self.value);
        rlp.append(&self.data);
        rlp.append(&self.v);
        rlp.append(&self.r);
        rlp.append(&self.s);
                                
        let data = &rlp.out();
                                
        let mut rlp = RlpStream::new();
        rlp.append(&(u32::from(PACKET_TRANSACTIONS)));
        let mut compressed = Vec::new();
        let len = parity_snappy::compress_into(data, &mut compressed);
        let payload = &compressed[0..len];
        rlp.append_raw(payload, 1);

        //
        let payload = &rlp.out();
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


#[cfg(test)]
mod tests{
    #[test]
    fn rplt() {
        use crate::lil_rlp;
        use crate::hash160::Hash160;
        use crate::hash256::Hash256;
        use super::*;
        use std::str::FromStr;

        let mut tx = Tx2 {
            nonce: U256::from(2),
            gas_price: U256::from(1_000_000_000u64),
            gas: U256::from(21_000),
            call: Address::from_str("2217F561635a924F2C7ad1149Ca1dCf35Eaee961").unwrap(),
            value: U256::from(10),
            data: Vec::new(),
            hash: H256::zero(),
            public: None, 
            r: U256::zero(),
            s: U256::zero(),
            v: 0u64,
            sender: Address::zero(),
        };
        let sec = Secret::from_str("426ab013650cbe3c615c2455fb414130ce45ca67e7205cb3104ec79a57ef1227").unwrap();
        tx = tx.sign(&sec, Some(123));

        let mut rlp = RlpStream::new_list(1);
        rlp.begin_list(9);
        rlp.append(&tx.nonce);
        rlp.append(&tx.gas_price);
        rlp.append(&tx.gas);
        rlp.append(&tx.call);
        rlp.append(&tx.value);
        rlp.append(&tx.data);
        rlp.append(&tx.v);
        rlp.append(&tx.r);
        rlp.append(&tx.s);

        println!("v:{:?}",&tx.v);
        println!("r:{:?}",&tx.r);
        println!("s:{:?}",&tx.s);

        //rlp.append(&0x80u8);

        let mut payload:Vec<u8> = vec![];//f8 67
        let n: u128 = 2;
        let gas_price: u128 = 1_000_000_000u128;
        let gas:u128 = 21_000u128;
        let value:u128 = 10;
        let data: Vec<u8> = vec![];
        let v = 282;
        let a: &[u64;4] = &tx.r.0;
        let aa:Vec<u8> = a.iter().rev().map(|a|a.to_be_bytes().to_vec()).flatten().collect();
        let b: &[u64;4] = &tx.s.0;
        let bb:Vec<u8> = b.iter().rev().map(|a|a.to_be_bytes().to_vec()).flatten().collect();

        let c: &[u8] = &tx.call.0;
        let cc: Vec<u8> = c.iter().map(|a|*a).collect();

        println!("flat: {:x?}", &aa);
        println!("flat: {:x?}", &bb);
        println!("flat: {:x?}", &cc);
        
        payload.push(0xf8);
        payload.push(0x67);
        lil_rlp::put_num(&mut payload, n); //+ 
        lil_rlp::put_num(&mut payload, gas_price); //+
        lil_rlp::put_num(&mut payload, gas);
        lil_rlp::put_str(&mut payload, &cc);
        lil_rlp::put_num(&mut payload, value);
        lil_rlp::put_str(&mut payload, &data);
        lil_rlp::put_num(&mut payload, v);
        lil_rlp::put_str(&mut payload, &aa);
        lil_rlp::put_str(&mut payload, &bb);

        // create list9 in list1
        println!("out: {:x?}", lil_rlp::as_list(&payload));
        println!("rlp: {:x?}", &rlp.out());

        /*[f8, 65, 
            2, 
            84, 3b, 9a, ca, 
            0, 
            82, 52, 8, 94, 22, 17, f5, 61, 63, 5a, 92, 4f, 2c, 7a, d1, 14, 9c, a1, dc, f3, 5e, ae, e9, 61, 
            a, 
                80, 82, 1, 1a, 
                a0, 
                    bd, fa, c2, 8b, e0, d7, a3, cf, 17, c7, bb, 32, cb, f3, d9, ce, b0, 18, c6, 89, 12, 3e, 3d, 65, bd, e8, a2, 8f, a, fc, c8, 8f,
                a0, 
                    e2, 32, 26, 84, 3b, 7d, 6b, 89, aa, b1, cc, 85, 50, 1, 31, d9, aa, 35, 29, fd, d3, 52, 51, 7, 3d, a0, a6, 5e, ad, 95, e8, 9b
        ] */
        /*rlp:[f8, 67, f8, 65,
            2, 
            84, 3b, 9a, ca, 
            0, 
            82, 52, 8, 94, 
            22, 17, f5, 61, 63, 5a, 92, 4f, 2c, 7a, d1, 14, 9c, a1, dc, f3, 5e, ae, e9, 61,
            a, 
                80, 82, 1, 1a, 
            a0, 
                bd, e8, a2, 8f, a, fc, c8, 8f, 
                b0, 18, c6, 89, 12, 3e, 3d, 65,
                17, c7, bb, 32, cb, f3, d9, ce,
                bd, fa, c2, 8b, e0, d7, a3, cf, 
                    a0, 
                3d, a0, a6, 5e, ad, 95, e8, 9b, 
                aa, 35, 29, fd, d3, 52, 51, 7,
                aa, b1, cc, 85, 50, 1, 31, d9, 
                e2, 32, 26, 84, 3b, 7d, 6b, 89] */

        //assert_eq!(rlp.out(), lil_rlp::as_list(&payload));
        assert_eq!(1,1);
    }
}