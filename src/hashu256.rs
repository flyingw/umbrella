
pub struct HashU256([u64; 4]);

impl HashU256 {
  
  #[inline]
  pub fn as_bytes(&self) -> &[u64] {
    &self.0
  }

  pub fn from_slice(d: &[u8]) -> Self {
    println!("d={:?}", d);
    
    let mut res: [u64;4] = [0u64;4];
    for (chunk, r) in d.chunks(8).zip(res.iter_mut()) {
  
      let mut shift: u8 = 0;
      for byte in chunk {

        // 51 149

        *r = (*r << shift) | (*byte as u64);
        // 59
        // *r = *r << 8 | byte

        println!("b={}", *r);
        // *r |=(*r << shift) | (*byte as u64);

        shift = shift + 8;
      }
    }


    HashU256(res)
  }
}