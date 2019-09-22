use core::slice::Iter;

pub fn list_size(iter: &mut Iter<u8>) -> Option<usize> {
    let n = iter.next()?;
    if (n >= &0xc0u8) && (n <= &0xf7u8) {
        Some((n - &0xc0u8) as usize)
    } else if (n >= &0xf8u8) && (n <= &0xffu8) {
        let len: usize = (n - &0xf7u8) as usize;
        if len > 8 { panic!("out of limit usize") };
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes[8 - len..].iter_mut().zip(iter.take(len)).for_each(|(res, d)| {
            *res = *d
        });
        Some(usize::from_be_bytes(bytes))
    } else {
        panic!("not a list")
    }
}

pub fn get_str(iter: &mut Iter<u8>) -> Option<Vec<u8>> {
    let n = iter.next()?;
    let str_len: usize = if (n >= &0x80u8) && (n <= &0xb7u8) {
        (n - &0x80u8) as usize
    } else if (n >= &0xb8u8) && (n <= &0xbfu8) {
        let len: usize = (n - &0xb7u8) as usize;
        if len > 8 { panic!("out of limit usize") };
        let mut bytes: [u8; 8] = [0u8; 8];
        bytes[8 - len..].iter_mut().zip(iter.take(len)).for_each(|(res, d)| {
            *res = *d
        });
        usize::from_be_bytes(bytes)
    } else {
        panic!("not a str")
    };
    Some(iter.take(str_len).map(|x| *x).collect())
}

pub fn get_num(iter: &mut Iter<u8>) -> Option<u128> {
    let n = iter.next()?;
    if n < &0x80u8 {
        Some(u128::from(*n))
    } else if (n >= &0x80u8) && (n <= &0xb7u8) {
        let len: usize = (n - &0x80u8) as usize;
        if len > 16 { panic!("out of limit u128") };
        let mut bytes: [u8; 16] = [0u8; 16];
        bytes[16 - len..].iter_mut().zip(iter).for_each(|(res, d)| {
            *res = *d
        });
        Some(u128::from_be_bytes(bytes))
    } else if (n >= &0xb8u8) && (n <= &0xbfu8) {
        panic!("too big num")
    } else {
        panic!("not a num")
    }
}
