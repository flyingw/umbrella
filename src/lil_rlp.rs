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

pub fn put_num(buf: &mut Vec<u8>, n: u128) {
    if n == 0 {
        buf.push(0x80u8)
    } else if n <= 0x7f {
        buf.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().skip_while(|x| *x == &0x0u8).map(|x| *x).collect();
        let size = 0x80u8 + (bytes.len() as u8);
        buf.push(size);
        buf.extend_from_slice(&bytes);
    }
}

pub fn put_str(buf: &mut Vec<u8>, bytes: &Vec<u8>) {
    if bytes.len() < 55 {
        buf.push(0x80u8 + (bytes.len() as u8));
        buf.extend_from_slice(&bytes);
    } else {
        let len_bytes: Vec<u8> = buf.len().to_be_bytes().iter().skip_while(|x| *x == &0x0u8).map(|x| *x).collect();
        buf.push(0xb7u8 + (len_bytes.len() as u8));
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(&bytes);
    }
}

pub fn as_list(bytes: &Vec<u8>) -> Vec<u8> {
    if bytes.len() < 55 {
        let mut buf = Vec::with_capacity(1 + bytes.len());
        buf.push(0xc0u8 + (bytes.len() as u8));
        buf.extend_from_slice(&bytes);
        buf
    } else {
        let len_bytes: Vec<u8> = bytes.len().to_be_bytes().iter().skip_while(|x| *x == &0x0u8).map(|x| *x).collect();
        let mut buf = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        buf.push(0xf7u8 + (len_bytes.len() as u8));
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(&bytes);
        buf
    }
}
