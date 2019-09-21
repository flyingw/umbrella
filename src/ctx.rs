use aes_ctr::Aes256Ctr;
use super::connection::OriginatedEncryptedConnection;

/// Messages serialization context

pub trait Ctx {
    fn encoder(&mut self) -> &mut Aes256Ctr;
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> ();
    fn update_remote_mac(&mut self, buf: &[u8]) -> ();
}

impl Ctx for () {
    fn encoder(&mut self) -> &mut Aes256Ctr{ panic!("no encoder in empty context."); }
    fn get_remote_mac(&mut self, _buf: &mut [u8]) -> (){}
    fn update_remote_mac(&mut self, _buf: &[u8]) -> (){}
}

impl Ctx for OriginatedEncryptedConnection {
    fn encoder(&mut self) -> &mut Aes256Ctr{ 
        &mut self.encoder
    }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () {
        self.egress_mac.clone().finalize(buf);
    }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){
        self.egress_mac.update(buf);
    }
}

impl Ctx for &mut OriginatedEncryptedConnection {
    fn encoder(&mut self) -> &mut Aes256Ctr{
        &mut self.encoder
    }
    fn get_remote_mac(&mut self, buf: &mut [u8]) -> () {
        self.egress_mac.clone().finalize(buf);
    }
    fn update_remote_mac(&mut self, buf: &[u8]) -> (){
        self.egress_mac.update(buf);
    }
}
