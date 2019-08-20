//! Functions to convert data to and from mnemonic words

use ring::digest::{digest, SHA256};
use std::str;
use crate::result::{Error, Result};
use crate::bits::Bits;

/// Wordlist language
pub enum Wordlist {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

/// Loads the word list for a given language
pub fn load_wordlist(wordlist: Wordlist) -> Vec<String> {
    match wordlist {
        Wordlist::ChineseSimplified => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_simplified.txt"))
        }
        Wordlist::ChineseTraditional => {
            load_wordlist_internal(include_bytes!("wordlists/chinese_traditional.txt"))
        }
        Wordlist::English => load_wordlist_internal(include_bytes!("wordlists/english.txt")),
        Wordlist::French => load_wordlist_internal(include_bytes!("wordlists/french.txt")),
        Wordlist::Italian => load_wordlist_internal(include_bytes!("wordlists/italian.txt")),
        Wordlist::Japanese => load_wordlist_internal(include_bytes!("wordlists/japanese.txt")),
        Wordlist::Korean => load_wordlist_internal(include_bytes!("wordlists/korean.txt")),
        Wordlist::Spanish => load_wordlist_internal(include_bytes!("wordlists/spanish.txt")),
    }
}

fn load_wordlist_internal(bytes: &[u8]) -> Vec<String> {
    let text: String = str::from_utf8(bytes).unwrap().to_string();
    text.lines().map(|s| s.to_string()).collect()
}

/// Encodes data into a mnemonic using BIP-39
pub fn mnemonic_encode(data: &[u8], word_list: &[String]) -> Vec<String> {
    let hash = digest(&SHA256, &data);
    let mut words = Vec::with_capacity((data.len() * 8 + data.len() / 32 + 10) / 11);
    let mut bits = Bits::from_slice(data, data.len() * 8);
    bits.append(&Bits::from_slice(hash.as_ref(), data.len() / 4));
    for i in 0..bits.len / 11 {
        words.push(word_list[bits.extract(i * 11, 11) as usize].clone());
    }
    let rem = bits.len % 11;
    if rem != 0 {
        let n = bits.extract(bits.len / 11 * 11, rem) << (8 - rem);
        words.push(word_list[n as usize].clone());
    }
    words
}

/// Decodes a neumonic into data using BIP-39
pub fn mnemonic_decode(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>> {
    let mut bits = Bits::with_capacity(mnemonic.len() * 11);
    for word in mnemonic {
        let value = match word_list.binary_search(word) {
            Ok(value) => value,
            Err(_) => return Err(Error::BadArgument(format!("Bad word: {}", word))),
        };
        let word_bits = Bits::from_slice(&[(value >> 3) as u8, ((value & 7) as u8) << 5], 11);
        bits.append(&word_bits);
    }
    let data_len = bits.len * 32 / 33;
    let cs_len = bits.len / 33;
    let cs = digest(&SHA256, &bits.data[0..data_len / 8]);
    let cs_bits = Bits::from_slice(cs.as_ref(), cs_len);
    if cs_bits.extract(0, cs_len) != bits.extract(data_len, cs_len) {
        return Err(Error::BadArgument("Invalid checksum".to_string()));
    }
    Ok(bits.data[0..data_len / 8].to_vec())
}
