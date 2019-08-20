use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hex;
use super::block_header::BlockHeader;
use super::message::Payload;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use crate::var_int;
use crate::hash256::{sha256d, Hash256};
use crate::result::{Error, Result};
use crate::serdes::Serializable;


/// A block header and partial merkle tree for SPV nodes to validate transactions
#[derive(Default, PartialEq, Eq, Hash, Clone)]
pub struct MerkleBlock {
    /// Block header
    pub header: BlockHeader,
    /// Number of transactions in the block
    pub total_transactions: u32,
    /// Hashes in depth-first order
    pub hashes: Vec<Hash256>,
    /// Bit vector used to assign hashes to nodes in the partial merkle tree
    pub flags: Vec<u8>,
}

impl MerkleBlock {
    /// Validates the merkle block and partial merkle tree and returns the set of matched transactions
    pub fn validate(&self) -> Result<Vec<Hash256>> {
        if self.total_transactions == 0 {
            return Err(Error::BadData("No transactions".to_string()));
        }

        let mut preorder_node = 0;
        let mut flag_bits_used = 0;
        let mut hashes_used = 0;
        let mut matches = Vec::new();
        let tree_depth = (self.total_transactions as f32).log(2.).ceil() as usize;
        let mut row_len = self.total_transactions as usize;
        let mut total_nodes = row_len as usize;
        while row_len > 1 {
            row_len = (row_len + 1) / 2;
            total_nodes += row_len;
        }

        let merkle_root = self.traverse(
            &mut preorder_node,
            &mut flag_bits_used,
            &mut hashes_used,
            0,
            tree_depth,
            total_nodes,
            &mut matches,
        )?;

        if merkle_root != self.header.merkle_root {
            return Err(Error::BadData("Merkle root doesn't match".to_string()));
        }

        if hashes_used < self.hashes.len() {
            return Err(Error::BadData("Not all hashes consumed".to_string()));
        }

        if preorder_node < total_nodes {
            return Err(Error::BadData("Not all nodes consumed".to_string()));
        }

        if (flag_bits_used + 7) / 8 < self.flags.len() {
            return Err(Error::BadData("Not all flag bits consumed".to_string()));
        }

        Ok(matches)
    }

    fn traverse(
        &self,
        preorder_node: &mut usize,
        flag_bits_used: &mut usize,
        hashes_used: &mut usize,
        depth: usize,
        tree_depth: usize,
        total_nodes: usize,
        matches: &mut Vec<Hash256>,
    ) -> Result<Hash256> {
        let flag = self.consume_flag(flag_bits_used)?;
        if flag == 0 {
            *preorder_node += (1 << (tree_depth - depth + 1)) - 1;
            let hash = self.consume_hash(hashes_used)?;
            Ok(hash)
        } else if depth == tree_depth {
            *preorder_node += 1;
            let hash = self.consume_hash(hashes_used)?;
            matches.push(hash.clone());
            Ok(hash)
        } else {
            *preorder_node += 1;
            let left = self.traverse(
                preorder_node,
                flag_bits_used,
                hashes_used,
                depth + 1,
                tree_depth,
                total_nodes,
                matches,
            )?;
            if *preorder_node >= total_nodes {
                let mut concat = Vec::with_capacity(64);
                concat.extend_from_slice(&left.0);
                concat.extend_from_slice(&left.0);
                Ok(sha256d(&concat))
            } else {
                let right = self.traverse(
                    preorder_node,
                    flag_bits_used,
                    hashes_used,
                    depth + 1,
                    tree_depth,
                    total_nodes,
                    matches,
                )?;
                if left == right {
                    return Err(Error::BadData("Duplicate transactions".to_string()));
                } else {
                    let mut concat = Vec::with_capacity(64);
                    concat.extend_from_slice(&left.0);
                    concat.extend_from_slice(&right.0);
                    Ok(sha256d(&concat))
                }
            }
        }
    }

    fn consume_flag(&self, flag_bits_used: &mut usize) -> Result<u8> {
        if *flag_bits_used / 8 >= self.flags.len() {
            return Err(Error::BadData("Not enough flag bits".to_string()));
        }
        let flag = (self.flags[*flag_bits_used / 8] >> *flag_bits_used % 8) & 1;
        *flag_bits_used += 1;
        Ok(flag)
    }

    fn consume_hash(&self, hashes_used: &mut usize) -> Result<Hash256> {
        if *hashes_used >= self.hashes.len() {
            return Err(Error::BadData("Not enough hashes".to_string()));
        }
        let hash = self.hashes[*hashes_used];
        *hashes_used += 1;
        Ok(hash)
    }
}

impl Serializable<MerkleBlock> for MerkleBlock {
    fn read(reader: &mut dyn Read) -> Result<MerkleBlock> {
        let header = BlockHeader::read(reader)?;
        let total_transactions = reader.read_u32::<LittleEndian>()?;
        let num_hashes = var_int::read(reader)?;
        let mut hashes = Vec::with_capacity(num_hashes as usize);
        for _i in 0..num_hashes {
            hashes.push(Hash256::read(reader)?);
        }
        let flags_len = var_int::read(reader)?;
        let mut flags = vec![0; flags_len as usize];
        reader.read(&mut flags)?;
        Ok(MerkleBlock {
            header,
            total_transactions,
            hashes,
            flags,
        })
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        self.header.write(writer)?;
        writer.write_u32::<LittleEndian>(self.total_transactions)?;
        var_int::write(self.hashes.len() as u64, writer)?;
        for hash in self.hashes.iter() {
            hash.write(writer)?;
        }
        var_int::write(self.flags.len() as u64, writer)?;
        writer.write(&self.flags)?;
        Ok(())
    }
}

impl Payload<MerkleBlock> for MerkleBlock {
    fn size(&self) -> usize {
        self.header.size()
            + 4
            + var_int::size(self.hashes.len() as u64)
            + self.hashes.len() * 32
            + var_int::size(self.flags.len() as u64)
            + self.flags.len()
    }
}

impl fmt::Debug for MerkleBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MerkleBlock")
            .field("header", &self.header)
            .field("total_transactions", &self.total_transactions)
            .field("hashes", &self.hashes)
            .field("flags", &hex::encode(&self.flags))
            .finish()
    }
}
