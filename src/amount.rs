//! Functions to convert between different bitcoin denominations

use std::fmt;
use super::result::{Error, Result};

/// Denomination of a bitcoin amount
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Units {
    /// One bitcoin
    Bch,
    /// One millionth of a bitcoin
    Bits,
    /// One hundred millionth of a bitcoin
    Sats,
    /// One ether
    Eth,
}

impl Units {
    pub fn parse(s: &str) -> Result<Units> {
        let s = s.to_lowercase();
        if s == "bch" || s == "bitcoin" {
            return Ok(Units::Bch);
        } else if s == "bit" || s == "bits" {
            return Ok(Units::Bits);
        } else if s == "sat" || s == "sats" {
            return Ok(Units::Sats);
        } else if s == "eth" || s == "ethereum" {
            return Ok(Units::Eth);
        } else {
            let msg = format!("Unknown units: {}", s);
            return Err(Error::BadArgument(msg));
        }
    }
}

/// An amount of bitcoin in satoshis
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Amount(pub u64);

impl Amount {
    /// Creates from a given amount and unit
    pub fn from(amount: f64, units: Units) -> Amount {
        match units {
            Units::Bch  => Amount((amount * 100_000_000.) as u64),
            Units::Bits => Amount((amount * 100.) as u64),
            Units::Sats => Amount(amount as u64),
            Units::Eth  => Amount((amount * 100_000_000.) as u64),
        }
    }

    /// Converts the amount to a given unit
    pub fn to(&self, units: Units) -> f64 {
        match units {
            Units::Bch => self.0 as f64 / 100_000_000.,
            Units::Bits => self.0 as f64 / 100.,
            Units::Sats => self.0 as f64,
            Units::Eth => self.0 as f64 / 100_000_000.,
        }
    }
}
impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&format!("{} bch", self.to(Units::Bch)))
    }
}
