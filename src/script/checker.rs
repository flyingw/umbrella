use crate::messages::Tx;
use secp256k1::{Message, PublicKey, Secp256k1, Signature};
use crate::sighash::{sighash, SigHashCache, SIGHASH_FORKID};
use crate::result::{Error, Result};
use crate::amount::Amount;

/// Locktimes greater than or equal to this are interpreted as timestamps. Less then, block heights.
const LOCKTIME_THRESHOLD: i32 = 500000000;

/// Disables the relative lock time for the sequence field
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// When set, sequence uses time. When unset, it uses block height.
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = (1 << 22);

/// Checks that external values are correct in the script
pub trait Checker {
    /// Checks that a signature and public key validate within a script
    ///
    /// Script should already have all signatures removed if they existed.
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool>;

    /// Checks that the lock time is valid according to BIP 65
    fn check_locktime(&self, locktime: i32) -> Result<bool>;

    /// Checks that the relative lock time enforced by the sequence is valid according to BIP 112
    fn check_sequence(&self, sequence: i32) -> Result<bool>;
}

/// Script checker that fails all transaction checks
pub struct TransactionlessChecker {}

impl Checker for TransactionlessChecker {
    fn check_sig(&mut self, _sig: &[u8], _pubkey: &[u8], _script: &[u8]) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }

    fn check_locktime(&self, _locktime: i32) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }

    fn check_sequence(&self, _sequence: i32) -> Result<bool> {
        Err(Error::IllegalState("Illegal transaction check".to_string()))
    }
}

/// Checks that external values in a script are correct for a specific transaction spend
pub struct TransactionChecker<'a> {
    /// Spending transaction
    pub tx: &'a Tx,
    /// Cache for intermediate sighash values
    pub sig_hash_cache: &'a mut SigHashCache,
    /// Spending input for the script
    pub input: usize,
    /// Amount being spent
    pub amount: Amount,
    /// True if the signature must have SIGHASH_FORKID present, false if not
    pub require_sighash_forkid: bool,
}

impl<'a> Checker for TransactionChecker<'a> {
    fn check_sig(&mut self, sig: &[u8], pubkey: &[u8], script: &[u8]) -> Result<bool> {
        if sig.len() < 1 {
            return Err(Error::ScriptError("Signature too short".to_string()));
        }
        let sighash_type = sig[sig.len() - 1];
        if self.require_sighash_forkid && sighash_type & SIGHASH_FORKID == 0 {
            return Err(Error::ScriptError("SIGHASH_FORKID not present".to_string()));
        }
        let sig_hash = sighash(
            self.tx,
            self.input,
            script,
            self.amount,
            sighash_type,
            self.sig_hash_cache,
        )?;
        let der_sig = &sig[0..sig.len() - 1];
        let secp = Secp256k1::verification_only();
        let mut signature = Signature::from_der(&secp, der_sig)?;
        // OpenSSL-generated signatures may not be normalized, but libsecp256kq requires them to be
        signature.normalize_s(&secp);
        let message = Message::from_slice(&sig_hash.0)?;
        let public_key = PublicKey::from_slice(&secp, &pubkey)?;
        Ok(secp.verify(&message, &signature, &public_key).is_ok())
    }

    fn check_locktime(&self, locktime: i32) -> Result<bool> {
        if locktime < 0 {
            return Err(Error::ScriptError("locktime negative".to_string()));
        }
        if (locktime >= LOCKTIME_THRESHOLD && (self.tx.lock_time as i32) < LOCKTIME_THRESHOLD)
            || (locktime < LOCKTIME_THRESHOLD && (self.tx.lock_time as i32) >= LOCKTIME_THRESHOLD)
        {
            return Err(Error::ScriptError("locktime types different".to_string()));
        }
        if locktime > self.tx.lock_time as i32 {
            return Err(Error::ScriptError("locktime greater than tx".to_string()));
        }
        if self.tx.inputs[self.input].sequence == 0xffffffff {
            return Err(Error::ScriptError("sequence is 0xffffffff".to_string()));
        }
        Ok(true)
    }

    fn check_sequence(&self, sequence: i32) -> Result<bool> {
        if sequence < 0 {
            return Err(Error::ScriptError("sequence negative".to_string()));
        }
        let sequence = sequence as u32;
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(true);
        }
        if self.tx.version < 2 {
            return Err(Error::ScriptError("tx version less than 2".to_string()));
        }
        if self.tx.inputs[self.input].sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            let msg = "tx sequence disable flag set".to_string();
            return Err(Error::ScriptError(msg));
        }
        let sequence_masked = sequence & 0x0000ffff;
        let tx_sequence_masked = self.tx.inputs[self.input].sequence & 0x0000ffff;
        if (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG
            && tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG)
            || (sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG
                && sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            let msg = "sequence types different".to_string();
            return Err(Error::ScriptError(msg));
        }
        if sequence_masked > tx_sequence_masked {
            let msg = "sequence greater than tx".to_string();
            return Err(Error::ScriptError(msg));
        }
        Ok(true)
    }
}
