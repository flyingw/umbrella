use digest::{FixedOutput, Input};
use ring::digest::{digest, SHA1, SHA256};
use ripemd160::{Digest, Ripemd160};
use super::op_codes::*;
use super::stack::{decode_bool, decode_num, encode_num, encode_num_overflow, pop_bool, pop_num};
use super::{
    Checker, MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE,
};
use crate::sighash::SIGHASH_FORKID;
use crate::result::{Error, Result};
use crate::bits::{rshift,lshift};
use crate::hash160::hash160;
use crate::hash256::sha256d;

// Stack capacity defaults, which may exceeded
const STACK_CAPACITY: usize = 100;
const ALT_STACK_CAPACITY: usize = 10;

/// Executes a script
pub fn eval<T: Checker>(script: &[u8], checker: &mut T) -> Result<()> {
    let mut stack: Vec<Vec<u8>> = Vec::with_capacity(STACK_CAPACITY);
    let mut alt_stack: Vec<Vec<u8>> = Vec::with_capacity(ALT_STACK_CAPACITY);
    // True if executing current if/else branch, false if next else
    let mut branch_exec: Vec<bool> = Vec::new();
    let mut check_index = 0;
    let mut i = 0;
    let mut n_ops = 0;

    if script.len() > MAX_SCRIPT_SIZE {
        return Err(Error::ScriptError("Script too long".to_string()));
    }

    while i < script.len() {
        if branch_exec.len() > 0 && !branch_exec[branch_exec.len() - 1] {
            i = skip_branch(script, i, &mut n_ops);
            if i >= script.len() {
                break;
            }
        }

        if script[i] > OP_16 {
            n_ops += 1;
            if n_ops > MAX_OPS_PER_SCRIPT {
                return Err(Error::ScriptError("Too many operations".to_string()));
            }
        }

        match script[i] {
            OP_0 => stack.push(encode_num(0)?),
            OP_1NEGATE => stack.push(encode_num(-1)?),
            OP_1 => stack.push(encode_num(1)?),
            OP_2 => stack.push(encode_num(2)?),
            OP_3 => stack.push(encode_num(3)?),
            OP_4 => stack.push(encode_num(4)?),
            OP_5 => stack.push(encode_num(5)?),
            OP_6 => stack.push(encode_num(6)?),
            OP_7 => stack.push(encode_num(7)?),
            OP_8 => stack.push(encode_num(8)?),
            OP_9 => stack.push(encode_num(9)?),
            OP_10 => stack.push(encode_num(10)?),
            OP_11 => stack.push(encode_num(11)?),
            OP_12 => stack.push(encode_num(12)?),
            OP_13 => stack.push(encode_num(13)?),
            OP_14 => stack.push(encode_num(14)?),
            OP_15 => stack.push(encode_num(15)?),
            OP_16 => stack.push(encode_num(16)?),
            len @ 1..=75 => {
                remains(i + 1, len as usize, script)?;
                stack.push(script[i + 1..i + 1 + len as usize].to_vec());
            }
            OP_PUSHDATA1 => {
                remains(i + 1, 1, script)?;
                let len = script[i + 1] as usize;
                remains(i + 2, len, script)?;
                stack.push(script[i + 2..i + 2 + len].to_vec());
            }
            OP_PUSHDATA2 => {
                remains(i + 1, 2, script)?;
                let len = ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8);
                if len > MAX_SCRIPT_ELEMENT_SIZE {
                    let msg = "OP_PUSHDATA2 failed, len > MAX_SCRIPT_ELEMENT_SIZE".to_string();
                    return Err(Error::ScriptError(msg));
                }
                remains(i + 3, len, script)?;
                stack.push(script[i + 3..i + 3 + len].to_vec());
            }
            OP_PUSHDATA4 => {
                remains(i + 1, 4, script)?;
                let len = ((script[i + 1] as usize) << 0)
                    + ((script[i + 2] as usize) << 8)
                    + ((script[i + 3] as usize) << 16)
                    + ((script[i + 4] as usize) << 24);
                if len > MAX_SCRIPT_ELEMENT_SIZE {
                    let msg = "OP_PUSHDATA4 failed, len > MAX_SCRIPT_ELEMENT_SIZE".to_string();
                    return Err(Error::ScriptError(msg));
                }
                remains(i + 5, len, script)?;
                stack.push(script[i + 5..i + 5 + len].to_vec());
            }
            OP_NOP => {}
            OP_IF => branch_exec.push(pop_bool(&mut stack)?),
            OP_NOTIF => branch_exec.push(!pop_bool(&mut stack)?),
            OP_ELSE => {
                let len = branch_exec.len();
                if len == 0 {
                    let msg = "ELSE found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec[len - 1] = !branch_exec[len - 1];
            }
            OP_ENDIF => {
                if branch_exec.len() == 0 {
                    let msg = "ENDIF found without matching IF".to_string();
                    return Err(Error::ScriptError(msg));
                }
                branch_exec.pop().unwrap();
            }
            OP_VERIFY => {
                if !pop_bool(&mut stack)? {
                    return Err(Error::ScriptError("OP_VERIFY failed".to_string()));
                }
            }
            OP_RETURN => {
                return Err(Error::ScriptError("Hit OP_RETURN".to_string()));
            }
            OP_TOALTSTACK => {
                check_stack_size(1, &stack)?;
                alt_stack.push(stack.pop().unwrap());
            }
            OP_FROMALTSTACK => {
                check_stack_size(1, &alt_stack)?;
                stack.push(alt_stack.pop().unwrap());
            }
            OP_IFDUP => {
                check_stack_size(1, &stack)?;
                if decode_bool(&stack[stack.len() - 1]) {
                    let copy = stack[stack.len() - 1].clone();
                    stack.push(copy);
                }
            }
            OP_DEPTH => {
                let depth = stack.len() as i64;
                stack.push(encode_num(depth)?);
            }
            OP_DROP => {
                check_stack_size(1, &stack)?;
                stack.pop().unwrap();
            }
            OP_DUP => {
                check_stack_size(1, &stack)?;
                let copy = stack[stack.len() - 1].clone();
                stack.push(copy);
            }
            OP_NIP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                stack.remove(index);
            }
            OP_OVER => {
                check_stack_size(2, &stack)?;
                let copy = stack[stack.len() - 2].clone();
                stack.push(copy);
            }
            OP_PICK => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_PICK failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let copy = stack[stack.len() - n as usize - 1].clone();
                stack.push(copy);
            }
            OP_ROLL => {
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "OP_ROLL failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                check_stack_size(n as usize + 1, &stack)?;
                let index = stack.len() - n as usize - 1;
                let item = stack.remove(index);
                stack.push(item);
            }
            OP_ROT => {
                check_stack_size(3, &stack)?;
                let index = stack.len() - 3;
                let third = stack.remove(index);
                stack.push(third);
            }
            OP_SWAP => {
                check_stack_size(2, &stack)?;
                let index = stack.len() - 2;
                let second = stack.remove(index);
                stack.push(second);
            }
            OP_TUCK => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                stack.insert(len - 2, top);
            }
            OP_2DROP => {
                check_stack_size(2, &stack)?;
                stack.pop().unwrap();
                stack.pop().unwrap();
            }
            OP_2DUP => {
                check_stack_size(2, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                stack.push(second);
                stack.push(top);
            }
            OP_3DUP => {
                check_stack_size(3, &stack)?;
                let len = stack.len();
                let top = stack[len - 1].clone();
                let second = stack[len - 2].clone();
                let third = stack[len - 3].clone();
                stack.push(third);
                stack.push(second);
                stack.push(top);
            }
            OP_2OVER => {
                check_stack_size(4, &stack)?;
                let len = stack.len();
                let third = stack[len - 3].clone();
                let fourth = stack[len - 4].clone();
                stack.push(fourth);
                stack.push(third);
            }
            OP_2ROT => {
                check_stack_size(6, &stack)?;
                let index = stack.len() - 6;
                let sixth = stack.remove(index);
                let fifth = stack.remove(index);
                stack.push(sixth);
                stack.push(fifth);
            }
            OP_2SWAP => {
                check_stack_size(4, &stack)?;
                let index = stack.len() - 4;
                let fourth = stack.remove(index);
                let third = stack.remove(index);
                stack.push(fourth);
                stack.push(third);
            }
            OP_CAT => {
                check_stack_size(2, &stack)?;
                let top = stack.pop().unwrap();
                let mut second = stack.pop().unwrap();
                second.extend_from_slice(&top);
                if second.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    let msg = "OP_CAT failed, len > MAX_SCRIPT_ELEMENT_SIZE".to_string();
                    return Err(Error::ScriptError(msg));
                }
                stack.push(second);
            }
            OP_SPLIT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                let x = stack.pop().unwrap();
                if n < 0 {
                    let msg = "OP_SPLIT failed, n negative".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n > x.len() as i32 {
                    let msg = "OP_SPLIT failed, n out of range".to_string();
                    return Err(Error::ScriptError(msg));
                } else if n == 0 {
                    stack.push(encode_num(0)?);
                    stack.push(x);
                } else if n as usize == x.len() {
                    stack.push(x);
                    stack.push(encode_num(0)?);
                } else {
                    stack.push(x[..n as usize].to_vec());
                    stack.push(x[n as usize..].to_vec());
                }
            }
            OP_SIZE => {
                check_stack_size(1, &stack)?;
                let len = stack[stack.len() - 1].len();
                stack.push(encode_num(len as i64)?);
            }
            OP_AND => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_AND failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] & b[i]);
                }
                stack.push(result);
            }
            OP_OR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_OR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] | b[i]);
                }
                stack.push(result);
            }
            OP_XOR => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_XOR failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut result = Vec::with_capacity(a.len());
                for i in 0..a.len() {
                    result.push(a[i] ^ b[i]);
                }
                stack.push(result);
            }
            OP_INVERT => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop().unwrap();
                for i in 0..v.len() {
                    v[i] = !v[i];
                }
                stack.push(v);
            }
            OP_LSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let v = stack.pop().unwrap();
                stack.push(lshift(&v, n as usize));
            }
            OP_RSHIFT => {
                check_stack_size(2, &stack)?;
                let n = pop_num(&mut stack)?;
                if n < 0 {
                    let msg = "n must be non-negative".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let v = stack.pop().unwrap();
                stack.push(rshift(&v, n as usize));
            }
            OP_EQUAL => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_EQUAL failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if a == b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_EQUALVERIFY => {
                check_stack_size(2, &stack)?;
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a.len() != b.len() {
                    let msg = "OP_EQUALVERIFY failed, different sizes".to_string();
                    return Err(Error::ScriptError(msg));
                }
                if a != b {
                    let msg = "Operands are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_1ADD => {
                let mut x = pop_num(&mut stack)? as i64;
                x += 1;
                stack.push(encode_num_overflow(x)?);
            }
            OP_1SUB => {
                let mut x = pop_num(&mut stack)? as i64;
                x -= 1;
                stack.push(encode_num_overflow(x)?);
            }
            OP_NEGATE => {
                let mut x = pop_num(&mut stack)? as i64;
                x = -x;
                stack.push(encode_num(x)?);
            }
            OP_ABS => {
                let mut x = pop_num(&mut stack)? as i64;
                if x < 0 {
                    x = -x;
                }
                stack.push(encode_num(x)?);
            }
            OP_NOT => {
                let mut x = pop_num(&mut stack)? as i64;
                if x == 0 {
                    x = 1;
                } else {
                    x = 0;
                }
                stack.push(encode_num(x)?);
            }
            OP_0NOTEQUAL => {
                let mut x = pop_num(&mut stack)? as i64;
                if x == 0 {
                    x = 0;
                } else {
                    x = 1;
                }
                stack.push(encode_num(x)?);
            }
            OP_ADD => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                let sum = a + b;
                stack.push(encode_num_overflow(sum)?);
            }
            OP_SUB => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                let difference = b - a;
                stack.push(encode_num_overflow(difference)?);
            }
            OP_MUL => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                let product = a * b;
                stack.push(encode_num(product)?);
            }
            OP_DIV => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if b == 0 {
                    let msg = "OP_DIV failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let quotient = a / b;
                stack.push(encode_num(quotient)?);
            }
            OP_MOD => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if b == 0 {
                    let msg = "OP_MOD failed, divide by 0".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let remainder = a % b;
                stack.push(encode_num(remainder)?);
            }
            OP_BOOLAND => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a != 0 && b != 0 {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_BOOLOR => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a != 0 || b != 0 {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUMEQUAL => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a == b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUMEQUALVERIFY => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a != b {
                    let msg = "Numbers are not equal".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NUMNOTEQUAL => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a != b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_LESSTHAN => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a < b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_GREATERTHAN => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a > b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_LESSTHANOREQUAL => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a <= b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_GREATERTHANOREQUAL => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a >= b {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_MIN => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a < b {
                    stack.push(encode_num(a)?);
                } else {
                    stack.push(encode_num(b)?);
                }
            }
            OP_MAX => {
                let b = pop_num(&mut stack)? as i64;
                let a = pop_num(&mut stack)? as i64;
                if a > b {
                    stack.push(encode_num(a)?);
                } else {
                    stack.push(encode_num(b)?);
                }
            }
            OP_WITHIN => {
                let max = pop_num(&mut stack)? as i64;
                let min = pop_num(&mut stack)? as i64;
                let x = pop_num(&mut stack)? as i64;
                if x >= min && x < max {
                    stack.push(encode_num(1)?);
                } else {
                    stack.push(encode_num(0)?);
                }
            }
            OP_NUM2BIN => {
                check_stack_size(2, &stack)?;
                let m = pop_num(&mut stack)?;
                let mut n = stack.pop().unwrap();
                if m < 1 {
                    let msg = format!("OP_NUM2BIN failed. m too small: {}", m);
                    return Err(Error::ScriptError(msg));
                }
                if m > MAX_SCRIPT_ELEMENT_SIZE as i32 {
                    let msg = format!("OP_NUM2BIN failed. m too large: {}", m);
                    return Err(Error::ScriptError(msg));
                }
                let nlen = n.len();
                if m < nlen as i32 {
                    let msg = "OP_NUM2BIN failed. n longer than m".to_string();
                    return Err(Error::ScriptError(msg));
                }
                let mut v = Vec::with_capacity(m as usize);
                let mut neg = 0;
                if nlen > 0 {
                    neg = n[nlen - 1] & 128;
                    n[nlen - 1] &= 127;
                }
                for _ in n.len()..m as usize {
                    v.push(0);
                }
                for b in n.iter().rev() {
                    v.push(*b);
                }
                v[0] |= neg;
                stack.push(v);
            }
            OP_BIN2NUM => {
                check_stack_size(1, &stack)?;
                let mut v = stack.pop().unwrap();
                v.reverse();
                let n = decode_num(&v)?;
                let e = encode_num(n)?;
                stack.push(e);
            }
            OP_RIPEMD160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let mut ripemd160 = Ripemd160::new();
                ripemd160.process(v.as_ref());
                let result = ripemd160.fixed_result().to_vec();
                stack.push(result);
            }
            OP_SHA1 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = digest(&SHA1, &v);
                stack.push(result.as_ref().to_vec());
            }
            OP_SHA256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = digest(&SHA256, &v);
                stack.push(result.as_ref().to_vec());
            }
            OP_HASH160 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let hash160 = hash160(&v).0;
                stack.push(hash160.to_vec());
            }
            OP_HASH256 => {
                check_stack_size(1, &stack)?;
                let v = stack.pop().unwrap();
                let result = sha256d(&v).0;
                stack.push(result.as_ref().to_vec());
            }
            OP_CODESEPARATOR => {
                check_index = i + 1;
            }
            OP_CHECKSIG => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop().unwrap();
                let sig = stack.pop().unwrap();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                match checker.check_sig(&sig, &pubkey, &cleaned_script)? {
                    true => stack.push(encode_num(1)?),
                    false => stack.push(encode_num(0)?),
                }
            }
            OP_CHECKSIGVERIFY => {
                check_stack_size(2, &stack)?;
                let pubkey = stack.pop().unwrap();
                let sig = stack.pop().unwrap();
                let mut cleaned_script = script[check_index..].to_vec();
                if prefork(&sig) {
                    cleaned_script = remove_sig(&sig, &cleaned_script);
                }
                if !checker.check_sig(&sig, &pubkey, &cleaned_script)? {
                    return Err(Error::ScriptError("OP_CHECKSIGVERIFY failed".to_string()));
                }
            }
            OP_CHECKMULTISIG => {
                match check_multisig(&mut stack, checker, &script[check_index..], &mut n_ops)? {
                    true => stack.push(encode_num(1)?),
                    false => stack.push(encode_num(0)?),
                }
            }
            OP_CHECKMULTISIGVERIFY => {
                if !check_multisig(&mut stack, checker, &script[check_index..], &mut n_ops)? {
                    let msg = "OP_CHECKMULTISIGVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_CHECKLOCKTIMEVERIFY => {
                let locktime = pop_num(&mut stack)?;
                if !checker.check_locktime(locktime)? {
                    let msg = "OP_CHECKLOCKTIMEVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_CHECKSEQUENCEVERIFY => {
                let sequence = pop_num(&mut stack)?;
                if !checker.check_sequence(sequence)? {
                    let msg = "OP_CHECKSEQUENCEVERIFY failed".to_string();
                    return Err(Error::ScriptError(msg));
                }
            }
            OP_NOP1 => {}
            OP_NOP4 => {}
            OP_NOP5 => {}
            OP_NOP6 => {}
            OP_NOP7 => {}
            OP_NOP8 => {}
            OP_NOP9 => {}
            OP_NOP10 => {}
            _ => {
                let msg = format!("Bad opcode: {}, index {}", script[i], i);
                return Err(Error::ScriptError(msg));
            }
        }

        i = next_op(i, script);
    }

    if branch_exec.len() != 0 {
        return Err(Error::ScriptError("ENDIF missing".to_string()));
    }
    // We don't call pop_bool here because the final stack element can be longer than 4 bytes
    check_stack_size(1, &stack)?;
    if !decode_bool(&stack[stack.len() - 1]) {
        return Err(Error::ScriptError("Top of stack is false".to_string()));
    }
    Ok(())
}

#[inline]
fn check_multisig<T: Checker>(
    stack: &mut Vec<Vec<u8>>,
    checker: &mut T,
    script: &[u8],
    n_ops: &mut usize,
) -> Result<bool> {
    // Pop the keys
    let total = pop_num(stack)?;
    if total < 0 || total > MAX_PUBKEYS_PER_MULTISIG as i32 {
        return Err(Error::ScriptError("total out of range".to_string()));
    }
    check_stack_size(total as usize, &stack)?;
    let mut keys = Vec::with_capacity(total as usize);
    for _i in 0..total {
        keys.push(stack.pop().unwrap());
    }

    // Multisig does up to n_keys checksigs so it's equivalent to n_keys more operations
    *n_ops += keys.len();
    if *n_ops > MAX_OPS_PER_SCRIPT {
        return Err(Error::ScriptError("Too many operations".to_string()));
    }

    // Pop the sigs
    let required = pop_num(stack)?;
    if required < 0 || required > total {
        return Err(Error::ScriptError("required out of range".to_string()));
    }
    check_stack_size(required as usize, &stack)?;
    let mut sigs = Vec::with_capacity(required as usize);
    for _i in 0..required {
        sigs.push(stack.pop().unwrap());
    }

    // Pop one more off. This isn't used and can't be changed.
    check_stack_size(1, &stack)?;
    stack.pop().unwrap();

    // Remove signature for pre-fork scripts
    let mut cleaned_script = script.to_vec();
    for sig in sigs.iter() {
        if prefork(sig) {
            cleaned_script = remove_sig(sig, &cleaned_script);
        }
    }

    let mut key = 0;
    let mut sig = 0;
    while sig < sigs.len() {
        if key == keys.len() {
            return Ok(false);
        }
        if checker.check_sig(&sigs[sig], &keys[key], &cleaned_script)? {
            sig += 1;
        }
        key += 1;
    }
    Ok(true)
}

fn prefork(sig: &[u8]) -> bool {
    sig.len() > 0 && sig[sig.len() - 1] & SIGHASH_FORKID == 0
}

/// Removes any instances of the signature from the pk_script in pre-fork transactions
fn remove_sig<'a>(sig: &[u8], script: &[u8]) -> Vec<u8> {
    if sig.len() == 0 {
        return script.to_vec();
    }
    let mut result = Vec::with_capacity(script.len());
    let mut i = 0;
    let mut start = 0;
    while i + sig.len() <= script.len() {
        if script[i..i + sig.len()] == *sig {
            result.extend_from_slice(&script[start..i]);
            start = i + sig.len();
            i = start;
        } else {
            i = next_op(i, script);
        }
    }
    result.extend_from_slice(&script[start..]);
    result
}

#[inline]
fn check_stack_size(minsize: usize, stack: &Vec<Vec<u8>>) -> Result<()> {
    if stack.len() < minsize {
        let msg = format!("Stack too small: {}", minsize);
        return Err(Error::ScriptError(msg));
    }
    Ok(())
}

#[inline]
fn remains(i: usize, len: usize, script: &[u8]) -> Result<()> {
    if i + len > script.len() {
        Err(Error::ScriptError("Not enough data remaining".to_string()))
    } else {
        Ok(())
    }
}

/// Gets the next operation index in the script, or the script length if at the end
pub fn next_op(i: usize, script: &[u8]) -> usize {
    if i >= script.len() {
        return script.len();
    }
    let next = match script[i] {
        len @ 1..=75 => i + 1 + len as usize,
        OP_PUSHDATA1 => {
            if i + 2 > script.len() {
                return script.len();
            }
            i + 2 + script[i + 1] as usize
        }
        OP_PUSHDATA2 => {
            if i + 3 > script.len() {
                return script.len();
            }
            i + 3 + ((script[i + 1] as usize) << 0) + ((script[i + 2] as usize) << 8)
        }
        OP_PUSHDATA4 => {
            if i + 5 > script.len() {
                return script.len();
            }
            let len = ((script[i + 1] as usize) << 0)
                + ((script[i + 2] as usize) << 8)
                + ((script[i + 3] as usize) << 16)
                + ((script[i + 4] as usize) << 24);
            i + 5 + len
        }
        _ => i + 1,
    };
    let overflow = next > script.len();
    return if overflow { script.len() } else { next };
}

/// Skips over a branch of if/else and return the index of the next else or endif opcode
fn skip_branch(script: &[u8], mut i: usize, n_ops: &mut usize) -> usize {
    let mut sub = 0;
    while i < script.len() {
        if script[i] > OP_16 {
            *n_ops += 1;
        }
        match script[i] {
            OP_IF => sub += 1,
            OP_NOTIF => sub += 1,
            OP_ELSE => {
                if sub == 0 {
                    return i;
                }
            }
            OP_ENDIF => {
                if sub == 0 {
                    return i;
                }
                sub -= 1;
            }
            _ => {}
        }
        i = next_op(i, script);
    }
    script.len()
}
