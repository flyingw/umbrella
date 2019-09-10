use std::ops::{Index, IndexMut};
use core::slice::SliceIndex;
use core::ops::{BitXor, BitXorAssign};

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash128([u8; 16]);

impl Hash128 {
  #[inline]
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  #[inline]
  pub fn as_bytes_mut(&mut self) -> &mut [u8] {
    &mut self.0
  }

  pub fn from_slice(d: &[u8]) -> Self {
    assert_eq!(16, d.len());
    let mut hash = Hash128::default();
    hash.as_bytes_mut().copy_from_slice(d);
    hash
  }
}

impl<I> Index<I> for Hash128 where I: SliceIndex<[u8]> {
  type Output = I::Output;

  #[inline]
  fn index(&self, index: I) -> &I::Output {
    &self.as_bytes()[index]
  }
}

impl<I> IndexMut<I> for Hash128 where I: SliceIndex<[u8], Output = [u8]> {
  #[inline]
  fn index_mut(&mut self, idx: I) -> &mut I::Output {
    &mut self.as_bytes_mut()[idx]
  }
}

impl BitXor for Hash128 {
  type Output = Hash128;

  fn bitxor(self, x2: Hash128) -> Self::Output {
    let mut x1 = self.clone();
    x1 ^= x2;
    x1
  }
}

impl BitXorAssign for Hash128 {
  fn bitxor_assign(&mut self, x2: Hash128) {
    for (x1, x2) in self.as_bytes_mut().iter_mut().zip(x2.as_bytes()) {
      *x1 ^= x2;
    }
  }
}
