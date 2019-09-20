use super::message_header::{MessageHeader,SecHeader};
use super::ping::Ping;
use super::reject::Reject;
use super::send_cmpct::SendCmpct;
use super::fee_filter::FeeFilter;
use super::tx::Tx;
use super::version::Version;
use super::node_key::NodeKey;
use super::hello::Hello;
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::ctx::Ctx;
use secp256k1::key::SecretKey;

/// Checksum to use when there is an empty payload
pub const NO_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];

/// Max message payload size (32MB)
pub const MAX_PAYLOAD_SIZE: u32 = 0x02000000;

pub type ProtocolId = [u8; 3];

pub struct CapabilityInfo {
    pub protocol: ProtocolId,
    pub version: u8,
    pub packet_count: u8,
}

use rlp::{RlpStream, Encodable};

impl Encodable for CapabilityInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&&self.protocol[..]);
        s.append(&self.version);
    }
}
pub const ETH_PROTOCOL: ProtocolId = *b"eth";
pub const ETH_PROTOCOL_VERSION_63: (u8, u8) = (63, 0x11);
pub const ETH_63_CAPABILITY: CapabilityInfo = CapabilityInfo { 
    protocol: ETH_PROTOCOL,
    version: ETH_PROTOCOL_VERSION_63.0,
    packet_count: ETH_PROTOCOL_VERSION_63.1
};

/// Message commands for the header
pub mod commands {
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

    // [Fee filter command](https://en.bitcoin.it/wiki/Protocol_documentation#feefilter)
    pub const FEEFILTER: [u8; 12] = *b"feefilter\0\0\0";

    // [no such command]
    pub const HELLO: [u8; 12] = *b"hello\0\0\0\0\0\0\0";
    
}

/// Bitcoin peer-to-peer message with its payload
//#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Message {
    FeeFilter(FeeFilter),
    Other(String),
    Partial(MessageHeader),
    Ping(Ping),
    Pong(Ping),
    Reject(Reject),
    SendCmpct(SendCmpct),
    Tx(Tx),
    Verack,
    Version(Version),
    NodeKey(NodeKey),
    Hello(Hello),
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

        // Feefilter
        if header.command == commands::FEEFILTER {
            let payload = header.payload(reader)?;
            let feefilter = FeeFilter::read(&mut Cursor::new(payload))?;
            return Ok(Message::FeeFilter(feefilter));
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
    pub fn write(&self, writer: &mut dyn Write, magic: [u8; 4], ctx: &mut dyn Ctx) -> io::Result<()> {
        use self::commands::*;
        use std::convert::TryInto;
        match self {
            Message::Other(s) => Err(io::Error::new(io::ErrorKind::InvalidData, s.as_ref())),
            Message::Partial(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot write partial message".to_string(),
            )),
            Message::Ping(p) => write_with_payload(writer, PING, p, magic),
            Message::Pong(p) => write_with_payload(writer, PONG, p, magic),
            Message::Reject(p) => write_with_payload(writer, REJECT, p, magic),
            Message::FeeFilter(p) => write_with_payload(writer, FEEFILTER, p, magic),
            Message::SendCmpct(p) => write_with_payload(writer, SENDCMPCT, p, magic),
            Message::Tx(p) => write_with_payload(writer, TX, p, magic),
            Message::Verack => write_without_payload(writer, VERACK, magic),
            Message::Version(v) => write_with_payload(writer, VERSION, v, magic),
            Message::NodeKey(v) => v.write(writer, &mut ()),
            Message::Hello(h) => write_with_payload2(writer, HELLO, h, magic[..3].try_into().expect("shortened magic"), ctx, h.mac_encoder_key),
        }
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Message::Other(p) => f.write_str(&format!("{:#?}", p)),
            Message::Partial(h) => f.write_str(&format!("Partial {:#?}", h)),
            Message::Ping(p) => f.write_str(&format!("{:#?}", p)),
            Message::Pong(p) => f.debug_struct("Pong").field("nonce", &p.nonce).finish(),
            Message::FeeFilter(p) => f.write_str(&format!("{:#?}", p)),
            Message::Reject(p) => f.write_str(&format!("{:#?}", p)),
            Message::SendCmpct(p) => f.write_str(&format!("{:#?}", p)),
            Message::Tx(p) => f.write_str(&format!("{:#?}", p)),
            Message::Verack => f.write_str("Verack"),
            Message::Version(p) => f.write_str(&format!("{:#?}", p)),
            Message::NodeKey(v) => f.write_str(&format!("{:#?}", v)),
            Message::Hello(h) => f.write_str(&format!("{:#?}", h)),
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
    header.write(writer, &mut ())
}

fn write_with_payload2<T:Serializable<T>>(
    writer: &mut dyn Write,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 3],
    ctx: &mut dyn Ctx,
    secret: SecretKey,
) -> io::Result<()>{
    debug!("  cmd: {:?}", command);
    debug!("magic: {:?}", magic);
    debug!(" size: {:?}", payload.size());

    let header = SecHeader{
        magic,
        command, 
        payload_size: payload.size() as u32,
        secret: secret,
    };

    debug!("header {:?}", &header);
    header.write(writer, ctx)?;

    payload.write(writer, ctx)
}

fn write_with_payload<T: Serializable<T>>(
    writer: &mut dyn Write,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 4],
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(payload.size());
    payload.write(&mut bytes, &mut ())?;
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

    header.write(writer, &mut ())?;
    payload.write(writer, &mut ())
}

/// Message payload that is writable to bytes
pub trait Payload<T>: Serializable<T> + fmt::Debug {
    fn size(&self) -> usize;
}
