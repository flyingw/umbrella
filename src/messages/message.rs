use super::addr::Addr;
use super::block::Block;
use super::block_locator::BlockLocator;
use super::fee_filter::FeeFilter;
use super::filter_add::FilterAdd;
use super::filter_load::FilterLoad;
use super::headers::Headers;
use super::inv::Inv;
use super::merkle_block::MerkleBlock;
use super::message_header::MessageHeader;
use super::ping::Ping;
use super::reject::Reject;
use super::send_cmpct::SendCmpct;
use super::tx::Tx;
use super::version::Version;
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use crate::result::{Error, Result};
use crate::serdes::Serializable;

/// Checksum to use when there is an empty payload
pub const NO_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];

/// Max message payload size (32MB)
pub const MAX_PAYLOAD_SIZE: u32 = 0x02000000;

/// Message commands for the header
pub mod commands {
    use std::collections::HashSet;

    /// [Addr command](https://en.bitcoin.it/wiki/Protocol_documentation#addr)
    pub const ADDR: [u8; 12] = *b"addr\0\0\0\0\0\0\0\0";

    /// [Alert command](https://en.bitcoin.it/wiki/Protocol_documentation#alert) (deprecated)
    pub const ALERT: [u8; 12] = *b"alert\0\0\0\0\0\0\0";

    /// [Block command](https://en.bitcoin.it/wiki/Protocol_documentation#block)
    pub const BLOCK: [u8; 12] = *b"block\0\0\0\0\0\0\0";

    /// [Block transaction command](https://en.bitcoin.it/wiki/Protocol_documentation#blocktxn)
    pub const BLOCKTXN: [u8; 12] = *b"blocktxn\0\0\0\0";

    /// [Compact block command](https://en.bitcoin.it/wiki/Protocol_documentation#cmpctblock)
    pub const CMPCTBLOCK: [u8; 12] = *b"cmpctblock\0\0";

    /// [Inventory command](https://en.bitcoin.it/wiki/Protocol_documentation#inv)
    pub const INV: [u8; 12] = *b"inv\0\0\0\0\0\0\0\0\0";

    /// [Fee filter command](https://en.bitcoin.it/wiki/Protocol_documentation#feefilter)
    pub const FEEFILTER: [u8; 12] = *b"feefilter\0\0\0";

    /// [Filter add command](https://en.bitcoin.it/wiki/Protocol_documentation#filterload.2C_filteradd.2C_filterclear.2C_merkleblock)
    pub const FILTERADD: [u8; 12] = *b"filteradd\0\0\0";

    /// [Filter clear command](https://en.bitcoin.it/wiki/Protocol_documentation#filterload.2C_filteradd.2C_filterclear.2C_merkleblock)
    pub const FILTERCLEAR: [u8; 12] = *b"filterclear\0";

    /// [Filter load command](https://en.bitcoin.it/wiki/Protocol_documentation#filterload.2C_filteradd.2C_filterclear.2C_merkleblock)
    pub const FILTERLOAD: [u8; 12] = *b"filterload\0\0";

    /// [Get addr command](https://en.bitcoin.it/wiki/Protocol_documentation#getaddr)
    pub const GETADDR: [u8; 12] = *b"getaddr\0\0\0\0\0";

    /// [Get blocks command](https://en.bitcoin.it/wiki/Protocol_documentation#getblocks)
    pub const GETBLOCKS: [u8; 12] = *b"getblocks\0\0\0";

    /// [Get block transaction command](https://en.bitcoin.it/wiki/Protocol_documentation#getblocktxn)
    pub const GETBLOCKTXN: [u8; 12] = *b"getblocktxn\0";

    /// [Get data command](https://en.bitcoin.it/wiki/Protocol_documentation#getdata)
    pub const GETDATA: [u8; 12] = *b"getdata\0\0\0\0\0";

    /// [Get headers command](https://en.bitcoin.it/wiki/Protocol_documentation#getheaders)
    pub const GETHEADERS: [u8; 12] = *b"getheaders\0\0";

    /// [Headers command](https://en.bitcoin.it/wiki/Protocol_documentation#headers)
    pub const HEADERS: [u8; 12] = *b"headers\0\0\0\0\0";

    /// [Mempool command](https://en.bitcoin.it/wiki/Protocol_documentation#mempool)
    pub const MEMPOOL: [u8; 12] = *b"mempool\0\0\0\0\0";

    /// [Merkle block](https://en.bitcoin.it/wiki/Protocol_documentation#filterload.2C_filteradd.2C_filterclear.2C_merkleblock)
    pub const MERKLEBLOCK: [u8; 12] = *b"merkleblock\0";

    /// [Not found command](https://en.bitcoin.it/wiki/Protocol_documentation#notfound)
    pub const NOTFOUND: [u8; 12] = *b"notfound\0\0\0\0";

    /// [Ping command](https://en.bitcoin.it/wiki/Protocol_documentation#ping)
    pub const PING: [u8; 12] = *b"ping\0\0\0\0\0\0\0\0";

    /// [Pong command](https://en.bitcoin.it/wiki/Protocol_documentation#pong)
    pub const PONG: [u8; 12] = *b"pong\0\0\0\0\0\0\0\0";

    /// [Reject command](https://en.bitcoin.it/wiki/Protocol_documentation#reject)
    pub const REJECT: [u8; 12] = *b"reject\0\0\0\0\0\0";

    /// [Send compact command](https://en.bitcoin.it/wiki/Protocol_documentation#sendcmpct)
    pub const SENDCMPCT: [u8; 12] = *b"sendcmpct\0\0\0";

    /// [Send headers command](https://en.bitcoin.it/wiki/Protocol_documentation#sendheaders)
    pub const SENDHEADERS: [u8; 12] = *b"sendheaders\0";

    /// [Transaction command](https://en.bitcoin.it/wiki/Protocol_documentation#tx)
    pub const TX: [u8; 12] = *b"tx\0\0\0\0\0\0\0\0\0\0";

    /// [Version command](https://en.bitcoin.it/wiki/Protocol_documentation#version)
    pub const VERSION: [u8; 12] = *b"version\0\0\0\0\0";

    /// [Version acknowledgement command](https://en.bitcoin.it/wiki/Protocol_documentation#verack)
    pub const VERACK: [u8; 12] = *b"verack\0\0\0\0\0\0";

    lazy_static! {
        /// Commands that this node is allowed to receive after handshake is complete.
        /// Includes everything but version and verack.
        pub static ref ALLOWED: HashSet<[u8; 12]> = {
            let mut s = HashSet::new();
            s.insert(ADDR);
            s.insert(ALERT);
            s.insert(BLOCK);
            s.insert(BLOCKTXN);
            s.insert(CMPCTBLOCK);
            s.insert(INV);
            s.insert(FEEFILTER);
            s.insert(FILTERADD);
            s.insert(FILTERCLEAR);
            s.insert(FILTERLOAD);
            s.insert(GETADDR);
            s.insert(GETBLOCKS);
            s.insert(GETBLOCKTXN);
            s.insert(GETDATA);
            s.insert(GETHEADERS);
            s.insert(HEADERS);
            s.insert(MEMPOOL);
            s.insert(MERKLEBLOCK);
            s.insert(NOTFOUND);
            s.insert(PING);
            s.insert(PONG);
            s.insert(REJECT);
            s.insert(SENDCMPCT);
            s.insert(SENDHEADERS);
            s.insert(TX);
            s
        };
    }
}

/// Bitcoin peer-to-peer message with its payload
#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Message {
    Addr(Addr),
    Block(Block),
    FeeFilter(FeeFilter),
    FilterAdd(FilterAdd),
    FilterClear,
    FilterLoad(FilterLoad),
    GetAddr,
    GetBlocks(BlockLocator),
    GetData(Inv),
    GetHeaders(BlockLocator),
    Headers(Headers),
    Inv(Inv),
    Mempool,
    MerkleBlock(MerkleBlock),
    NotFound(Inv),
    Other(String),
    Partial(MessageHeader),
    Ping(Ping),
    Pong(Ping),
    Reject(Reject),
    SendHeaders,
    SendCmpct(SendCmpct),
    Tx(Tx),
    Verack,
    Version(Version),
}

impl Message {
    /// Reads a Bitcoin P2P message with its payload from bytes
    ///
    /// It's possible for a message's header to be read but not its payload. In this case, the
    /// return value is not an Error but a Partial message, and the complete message may be read
    /// later using read_partial.
    pub fn read(reader: &mut dyn Read, magic: [u8; 4]) -> Result<Self> {
        let header = MessageHeader::read(reader)?;
        header.validate(magic, MAX_PAYLOAD_SIZE)?;
        match Message::read_partial(reader, &header) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                if let Error::IOError(ref e) = e {
                    // Depending on platform, either TimedOut or WouldBlock may be returned to indicate a non-error timeout
                    if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
                    {
                        return Ok(Message::Partial(header));
                    }
                }
                return Err(e);
            }
        }
    }

    /// Reads the complete message given a message header
    ///
    /// It may be used after read() returns Message::Partial.
    pub fn read_partial(reader: &mut dyn Read, header: &MessageHeader) -> Result<Self> {
        // Addr
        if header.command == commands::ADDR {
            let payload = header.payload(reader)?;
            let addr = Addr::read(&mut Cursor::new(payload))?;
            return Ok(Message::Addr(addr));
        }

        // Block
        if header.command == commands::BLOCK {
            let payload = header.payload(reader)?;
            let block = Block::read(&mut Cursor::new(payload))?;
            return Ok(Message::Block(block));
        }

        // Feefilter
        if header.command == commands::FEEFILTER {
            let payload = header.payload(reader)?;
            let feefilter = FeeFilter::read(&mut Cursor::new(payload))?;
            return Ok(Message::FeeFilter(feefilter));
        }

        // FilterAdd
        if header.command == commands::FILTERADD {
            let payload = header.payload(reader)?;
            let filter_add = FilterAdd::read(&mut Cursor::new(payload))?;
            filter_add.validate()?;
            return Ok(Message::FilterAdd(filter_add));
        }

        // FilterClear
        if header.command == commands::FILTERCLEAR {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::FilterClear);
        }

        // FilterLoad
        if header.command == commands::FILTERLOAD {
            let payload = header.payload(reader)?;
            let filter_load = FilterLoad::read(&mut Cursor::new(payload))?;
            filter_load.validate()?;
            return Ok(Message::FilterLoad(filter_load));
        }

        // Getaddr
        if header.command == commands::GETADDR {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::GetAddr);
        }

        // Getblocks
        if header.command == commands::GETBLOCKS {
            let payload = header.payload(reader)?;
            let block_locator = BlockLocator::read(&mut Cursor::new(payload))?;
            return Ok(Message::GetBlocks(block_locator));
        }

        // Getdata
        if header.command == commands::GETDATA {
            let payload = header.payload(reader)?;
            let inv = Inv::read(&mut Cursor::new(payload))?;
            return Ok(Message::GetData(inv));
        }

        // Getheaders
        if header.command == commands::GETHEADERS {
            let payload = header.payload(reader)?;
            let block_locator = BlockLocator::read(&mut Cursor::new(payload))?;
            return Ok(Message::GetHeaders(block_locator));
        }

        // Headers
        if header.command == commands::HEADERS {
            let payload = header.payload(reader)?;
            let headers = Headers::read(&mut Cursor::new(payload))?;
            return Ok(Message::Headers(headers));
        }

        // Inv
        if header.command == commands::INV {
            let payload = header.payload(reader)?;
            let inv = Inv::read(&mut Cursor::new(payload))?;
            return Ok(Message::Inv(inv));
        }

        // Mempool
        if header.command == commands::MEMPOOL {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::Mempool);
        }

        // MerkleBlock
        if header.command == commands::MERKLEBLOCK {
            let payload = header.payload(reader)?;
            let merkle_block = MerkleBlock::read(&mut Cursor::new(payload))?;
            return Ok(Message::MerkleBlock(merkle_block));
        }

        // Notfound
        if header.command == commands::NOTFOUND {
            let payload = header.payload(reader)?;
            let inv = Inv::read(&mut Cursor::new(payload))?;
            return Ok(Message::NotFound(inv));
        }

        // Ping
        if header.command == commands::PING {
            let payload = header.payload(reader)?;
            let ping = Ping::read(&mut Cursor::new(payload))?;
            return Ok(Message::Ping(ping));
        }

        // Pong
        if header.command == commands::PONG {
            let payload = header.payload(reader)?;
            let pong = Ping::read(&mut Cursor::new(payload))?;
            return Ok(Message::Pong(pong));
        }

        // Reject
        if header.command == commands::REJECT {
            let payload = header.payload(reader)?;
            let reject = Reject::read(&mut Cursor::new(payload))?;
            return Ok(Message::Reject(reject));
        }

        // Sendcmpct
        if header.command == commands::SENDCMPCT {
            let payload = header.payload(reader)?;
            let sendcmpct = SendCmpct::read(&mut Cursor::new(payload))?;
            return Ok(Message::SendCmpct(sendcmpct));
        }

        // Sendheaders
        if header.command == commands::SENDHEADERS {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::SendHeaders);
        }

        // Tx
        if header.command == commands::TX {
            let payload = header.payload(reader)?;
            let tx = Tx::read(&mut Cursor::new(payload))?;
            return Ok(Message::Tx(tx));
        }

        // Version
        if header.command == commands::VERSION {
            let payload = header.payload(reader)?;
            let version = Version::read(&mut Cursor::new(payload))?;
            version.validate()?;
            return Ok(Message::Version(version));
        }

        // Verack
        if header.command == commands::VERACK {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::Verack);
        }

        // Unknown message
        if header.payload_size > 0 {
            header.payload(reader)?;
        }
        let command = String::from_utf8(header.command.to_vec()).unwrap_or("Unknown".to_string());
        return Ok(Message::Other(command));
    }

    /// Writes a Bitcoin P2P message with its payload to bytes
    pub fn write(&self, writer: &mut dyn Write, magic: [u8; 4]) -> io::Result<()> {
        use self::commands::*;
        match self {
            Message::Addr(p) => write_with_payload(writer, ADDR, p, magic),
            Message::Block(p) => write_with_payload(writer, BLOCK, p, magic),
            Message::FeeFilter(p) => write_with_payload(writer, FEEFILTER, p, magic),
            Message::FilterAdd(p) => write_with_payload(writer, FILTERADD, p, magic),
            Message::FilterClear => write_without_payload(writer, FILTERCLEAR, magic),
            Message::FilterLoad(p) => write_with_payload(writer, FILTERLOAD, p, magic),
            Message::GetAddr => write_without_payload(writer, GETADDR, magic),
            Message::GetBlocks(p) => write_with_payload(writer, GETBLOCKS, p, magic),
            Message::GetData(p) => write_with_payload(writer, GETDATA, p, magic),
            Message::GetHeaders(p) => write_with_payload(writer, GETHEADERS, p, magic),
            Message::Headers(p) => write_with_payload(writer, HEADERS, p, magic),
            Message::Mempool => write_without_payload(writer, MEMPOOL, magic),
            Message::MerkleBlock(p) => write_with_payload(writer, MERKLEBLOCK, p, magic),
            Message::NotFound(p) => write_with_payload(writer, NOTFOUND, p, magic),
            Message::Inv(p) => write_with_payload(writer, INV, p, magic),
            Message::Other(s) => Err(io::Error::new(io::ErrorKind::InvalidData, s.as_ref())),
            Message::Partial(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot write partial message".to_string(),
            )),
            Message::Ping(p) => write_with_payload(writer, PING, p, magic),
            Message::Pong(p) => write_with_payload(writer, PONG, p, magic),
            Message::Reject(p) => write_with_payload(writer, REJECT, p, magic),
            Message::SendHeaders => write_without_payload(writer, SENDHEADERS, magic),
            Message::SendCmpct(p) => write_with_payload(writer, SENDCMPCT, p, magic),
            Message::Tx(p) => write_with_payload(writer, TX, p, magic),
            Message::Verack => write_without_payload(writer, VERACK, magic),
            Message::Version(v) => write_with_payload(writer, VERSION, v, magic),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Message::Addr(p) => f.write_str(&format!("{:#?}", p)),
            Message::Block(p) => f.write_str(&format!("{:#?}", p)),
            Message::FeeFilter(p) => f.write_str(&format!("{:#?}", p)),
            Message::FilterAdd(p) => f.write_str(&format!("{:#?}", p)),
            Message::FilterClear => f.write_str("FilterClear"),
            Message::FilterLoad(p) => f.write_str(&format!("{:#?}", p)),
            Message::GetAddr => f.write_str("GetAddr"),
            Message::GetBlocks(p) => f
                .debug_struct("GetBlocks")
                .field("version", &p.version)
                .field("block_locator_hashes", &p.block_locator_hashes)
                .field("hash_stop", &p.hash_stop)
                .finish(),
            Message::GetData(p) => f.debug_struct("GetData").field("inv", &p).finish(),
            Message::GetHeaders(p) => f
                .debug_struct("GetHeaders")
                .field("version", &p.version)
                .field("block_locator_hashes", &p.block_locator_hashes)
                .field("hash_stop", &p.hash_stop)
                .finish(),
            Message::Headers(p) => f.write_str(&format!("{:#?}", p)),
            Message::Inv(p) => f.write_str(&format!("{:#?}", p)),
            Message::Mempool => f.write_str("Mempool"),
            Message::MerkleBlock(p) => f.write_str(&format!("{:#?}", p)),
            Message::NotFound(p) => f.debug_struct("NotFound").field("inv", &p).finish(),
            Message::Other(p) => f.write_str(&format!("{:#?}", p)),
            Message::Partial(h) => f.write_str(&format!("Partial {:#?}", h)),
            Message::Ping(p) => f.write_str(&format!("{:#?}", p)),
            Message::Pong(p) => f.debug_struct("Pong").field("nonce", &p.nonce).finish(),
            Message::Reject(p) => f.write_str(&format!("{:#?}", p)),
            Message::SendHeaders => f.write_str("SendHeaders"),
            Message::SendCmpct(p) => f.write_str(&format!("{:#?}", p)),
            Message::Tx(p) => f.write_str(&format!("{:#?}", p)),
            Message::Verack => f.write_str("Verack"),
            Message::Version(p) => f.write_str(&format!("{:#?}", p)),
        }
    }
}

fn write_without_payload(
    writer: &mut dyn Write,
    command: [u8; 12],
    magic: [u8; 4],
) -> io::Result<()> {
    let header = MessageHeader {
        magic,
        command,
        payload_size: 0,
        checksum: NO_CHECKSUM,
    };
    header.write(writer)
}

fn write_with_payload<T: Serializable<T>>(
    writer: &mut dyn Write,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 4],
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(payload.size());
    payload.write(&mut bytes)?;
    let hash = digest::digest(&digest::SHA256, bytes.as_ref());
    let hash = digest::digest(&digest::SHA256, &hash.as_ref());
    let h = &hash.as_ref();
    let checksum = [h[0], h[1], h[2], h[3]];

    let header = MessageHeader {
        magic,
        command,
        payload_size: payload.size() as u32,
        checksum: checksum,
    };

    header.write(writer)?;
    payload.write(writer)
}

/// Message payload that is writable to bytes
pub trait Payload<T>: Serializable<T> + fmt::Debug {
    fn size(&self) -> usize;
}
