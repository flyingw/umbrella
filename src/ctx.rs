use aes_ctr::Aes256Ctr;
use super::connection::OriginatedEncryptedConnection;
use secp256k1::key::{SecretKey};

/// Messages serialization context

pub trait Ctx {
    fn decoder(&mut self) -> &mut Aes256Ctr;
    fn encoder(&mut self) -> &mut Aes256Ctr;
    fn secret_key(&mut self) -> &SecretKey;
    fn get_local_mac(&mut self, buf: &mut [u8]) -> ();
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> ();
    fn update_local_mac(&mut self, buf: &[u8]) -> ();
    fn update_remote_mac(&mut self, buf: &[u8]) -> ();
    fn expected(&mut self) -> [u8; 12];
}

impl Ctx for () {
    fn decoder(&mut self) -> &mut Aes256Ctr{ panic!("no decoder in empty context."); }
    fn encoder(&mut self) -> &mut Aes256Ctr{ panic!("no encoder in empty context."); }
    fn secret_key(&mut self) -> &SecretKey{ panic!("no secret_key in empty context."); }
    fn get_local_mac(&mut self, _buf: &mut [u8]) -> (){}
    fn get_remote_mac(&mut self, _buf: &mut [u8]) -> (){}
    fn update_local_mac(&mut self, _buf: &[u8]) -> (){}
    fn update_remote_mac(&mut self, _buf: &[u8]) -> (){}
    fn expected(&mut self) -> [u8; 12]{panic!("skip");}
}

impl Ctx for OriginatedEncryptedConnection {
    fn decoder(&mut self) -> &mut Aes256Ctr{ 
        &mut self.decoder
    }
    fn encoder(&mut self) -> &mut Aes256Ctr{ 
        &mut self.encoder
    }
    fn secret_key(&mut self) -> &SecretKey{
        &self.mac_encoder_key
    }
    fn get_local_mac(&mut self, buf: &mut [u8]) -> () {
        self.ingress_mac.clone().finalize(buf);
    }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () {
        self.egress_mac.clone().finalize(buf);
    }
    fn update_local_mac(&mut self, buf: &[u8]) -> (){
        self.ingress_mac.update(buf);
    }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){
        self.egress_mac.update(buf);
    }
    fn expected(&mut self) -> [u8; 12]{ 
        self.expected
    }
}

impl Ctx for &mut OriginatedEncryptedConnection {
    fn decoder(&mut self) -> &mut Aes256Ctr{
        &mut self.decoder
    }
    fn encoder(&mut self) -> &mut Aes256Ctr{
        &mut self.encoder
    }
    fn secret_key(&mut self) -> &SecretKey{
        &self.mac_encoder_key
    }
    fn get_local_mac(&mut self, buf: &mut [u8]) -> () {
        self.ingress_mac.clone().finalize(buf);
    }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () {
        self.egress_mac.clone().finalize(buf);
    }
    fn update_local_mac(&mut self, buf: &[u8]) -> (){
        self.ingress_mac.update(buf);
    }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){
        self.egress_mac.update(buf);
    }
    fn expected(&mut self) -> [u8; 12]{ 
        self.expected
    }
}
