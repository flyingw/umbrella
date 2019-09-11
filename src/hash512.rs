use std::ops::{Index, IndexMut};
use core::slice::SliceIndex;
use core::ops::{BitXor, BitXorAssign};

// #[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512([u8;64]);

impl Hash512 {
  #[inline]
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  #[inline]
  pub fn as_bytes_mut(&mut self) -> &mut [u8] {
    &mut self.0
  }

//   pub fn from_slice(d: &[u8]) -> Self {
//     assert_eq!(64, d.len());
//     let mut hash = Hash512::default();
//     hash.as_bytes_mut().copy_from_slice(d);
//     hash
//   }
  pub fn copy_from_slice(&mut self, d: &[u8]) {
    assert_eq!(64, d.len());
    self.as_bytes_mut().copy_from_slice(d);
  }
}

impl Default for Hash512 {
  fn default() -> Self { Hash512([0u8;64]) }
}

impl<I> Index<I> for Hash512 where I: SliceIndex<[u8]> {
  type Output = I::Output;

  #[inline]
  fn index(&self, index: I) -> &I::Output {
    &self.as_bytes()[index]
  }
}

impl<I> IndexMut<I> for Hash512 where I: SliceIndex<[u8], Output = [u8]> {
  #[inline]
  fn index_mut(&mut self, idx: I) -> &mut I::Output {
    &mut self.as_bytes_mut()[idx]
  }
}

// impl BitXor for Hash512 {
//   type Output = Hash512;

//   fn bitxor(self, x2: Hash512) -> Self::Output {
//     let mut x1 = self.clone();
//     x1 ^= x2;
//     x1
//   }
// }

// impl BitXorAssign for Hash512 {
//   fn bitxor_assign(&mut self, x2: Hash512) {
//     for (x1, x2) in self.as_bytes_mut().iter_mut().zip(x2.as_bytes()) {
//       *x1 ^= x2;
//     }
//   }
// }
