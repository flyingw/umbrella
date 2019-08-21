use super::addr::Addr;
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

    /// [Compact block command](https://en.bitcoin.it/wiki/Protocol_documentation#cmpctblock)
    pub const CMPCTBLOCK: [u8; 12] = *b"cmpctblock\0\0";

    /// [Get addr command](https://en.bitcoin.it/wiki/Protocol_documentation#getaddr)
    pub const GETADDR: [u8; 12] = *b"getaddr\0\0\0\0\0";

    /// [Mempool command](https://en.bitcoin.it/wiki/Protocol_documentation#mempool)
    pub const MEMPOOL: [u8; 12] = *b"mempool\0\0\0\0\0";

    /// [Ping command](https://en.bitcoin.it/wiki/Protocol_documentation#ping)
    pub const PING: [u8; 12] = *b"ping\0\0\0\0\0\0\0\0";

    /// [Pong command](https://en.bitcoin.it/wiki/Protocol_documentation#pong)
    pub const PONG: [u8; 12] = *b"pong\0\0\0\0\0\0\0\0";

    /// [Reject command](https://en.bitcoin.it/wiki/Protocol_documentation#reject)
    pub const REJECT: [u8; 12] = *b"reject\0\0\0\0\0\0";

    /// [Send compact command](https://en.bitcoin.it/wiki/Protocol_documentation#sendcmpct)
    pub const SENDCMPCT: [u8; 12] = *b"sendcmpct\0\0\0";

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
            s.insert(CMPCTBLOCK);
            s.insert(GETADDR);
            s.insert(MEMPOOL);
            s.insert(PING);
            s.insert(PONG);
            s.insert(REJECT);
            s.insert(SENDCMPCT);
            s.insert(TX);
            s
        };
    }
}

/// Bitcoin peer-to-peer message with its payload
#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Message {
    Addr(Addr),
    GetAddr,
    Mempool,
    Other(String),
    Partial(MessageHeader),
    Ping(Ping),
    Pong(Ping),
    Reject(Reject),
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

        // Getaddr
        if header.command == commands::GETADDR {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::GetAddr);
        }

        // Mempool
        if header.command == commands::MEMPOOL {
            if header.payload_size != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::Mempool);
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
            Message::GetAddr => write_without_payload(writer, GETADDR, magic),
            Message::Mempool => write_without_payload(writer, MEMPOOL, magic),
            Message::Other(s) => Err(io::Error::new(io::ErrorKind::InvalidData, s.as_ref())),
            Message::Partial(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot write partial message".to_string(),
            )),
            Message::Ping(p) => write_with_payload(writer, PING, p, magic),
            Message::Pong(p) => write_with_payload(writer, PONG, p, magic),
            Message::Reject(p) => write_with_payload(writer, REJECT, p, magic),
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
            Message::GetAddr => f.write_str("GetAddr"),
            Message::Mempool => f.write_str("Mempool"),
            Message::Other(p) => f.write_str(&format!("{:#?}", p)),
            Message::Partial(h) => f.write_str(&format!("Partial {:#?}", h)),
            Message::Ping(p) => f.write_str(&format!("{:#?}", p)),
            Message::Pong(p) => f.debug_struct("Pong").field("nonce", &p.nonce).finish(),
            Message::Reject(p) => f.write_str(&format!("{:#?}", p)),
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
