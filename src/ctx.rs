use aes_ctr::Aes256Ctr;
use secp256k1::key::{PublicKey, SecretKey};
use tiny_keccak::Keccak;


/// Encrypted Messages serialization context
pub struct EncCtx {
	pub public_key: PublicKey,
	pub encoder: Aes256Ctr,
	pub decoder: Aes256Ctr,
	pub mac_encoder_key: SecretKey,
	pub egress_mac: Keccak,
	pub ingress_mac: Keccak,
    pub expected:[u8; 12],
}

pub trait Ctx {
    fn decoder(&mut self) -> &mut Aes256Ctr;
    fn encoder(&mut self) -> &mut Aes256Ctr;
    fn secret_key(&mut self) -> &SecretKey;
    fn get_local_mac(&mut self, buf: &mut [u8]) -> ();
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> ();
    fn update_local_mac(&mut self, buf: &[u8]) -> ();
    fn update_remote_mac(&mut self, buf: &[u8]) -> ();
    fn expected(&mut self) -> [u8; 12];
    fn expect(&mut self, ex: [u8;12]) -> ();
}

impl Ctx for () {
    fn decoder(&mut self) -> &mut Aes256Ctr{ panic!("no decoder in empty context"); }
    fn encoder(&mut self) -> &mut Aes256Ctr{ panic!("no encoder in empty context"); }
    fn secret_key(&mut self) -> &SecretKey { panic!("no secret  in empty context"); }
    fn get_local_mac(&mut self,_buf: &mut [u8])   -> (){}
    fn get_remote_mac(&mut self, _buf: &mut [u8]) -> (){}
    fn update_local_mac(&mut self, _buf: &[u8])   -> (){}
    fn update_remote_mac(&mut self,  _buf: &[u8]) -> (){}
    fn expected(&mut self) -> [u8; 12]{ panic!("skip"); }
    fn expect(&mut self, _ex: [u8;12]) -> () {}
}

impl Ctx for EncCtx {
    fn decoder(&mut self) -> &mut Aes256Ctr{  &mut self.decoder }
    fn encoder(&mut self) -> &mut Aes256Ctr{  &mut self.encoder }
    fn secret_key(&mut self) -> &SecretKey{ &self.mac_encoder_key }
    fn get_local_mac(&mut self, buf: &mut [u8]) -> () { self.ingress_mac.clone().finalize(buf); }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () { self.egress_mac.clone().finalize(buf); }
    fn update_local_mac(&mut self, buf: &[u8]) -> (){ self.ingress_mac.update(buf); }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){ self.egress_mac.update(buf); }
    fn expected(&mut self) -> [u8; 12]{ self.expected }
    fn expect(&mut self, ex: [u8;12]) -> (){ self.expected = ex; }
}

impl Ctx for &mut EncCtx {
    fn decoder(&mut self) -> &mut Aes256Ctr{ &mut self.decoder}
    fn encoder(&mut self) -> &mut Aes256Ctr{ &mut self.encoder }
    fn secret_key(&mut self) -> &SecretKey{ &self.mac_encoder_key }
    fn get_local_mac(&mut self, buf: &mut [u8]) -> () { self.ingress_mac.clone().finalize(buf); }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () { self.egress_mac.clone().finalize(buf); }
    fn update_local_mac(&mut self, buf: &[u8]) -> (){ self.ingress_mac.update(buf); }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){ self.egress_mac.update(buf); }
    fn expected(&mut self) -> [u8; 12]{ self.expected }
    fn expect(&mut self, ex: [u8;12]) -> (){ self.expected = ex; }
}
