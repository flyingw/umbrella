use super::message_header::{MessageHeader,SecHeader,MsgHeader};
use super::ping::Ping;
use super::reject::Reject;
use super::send_cmpct::SendCmpct;
use super::fee_filter::FeeFilter;
use super::tx::Tx;
use super::tx2::Tx2;
use super::version::Version;
use super::node_key::NodeKey;
use super::hello::Hello;
use super::status::Status;
use ring::digest;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use crate::result::{Error, Result};
use crate::serdes::Serializable;
use crate::ctx::Ctx;

/// Checksum to use when there is an empty payload
pub const NO_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];

/// Max message payload size (32MB)
pub const MAX_PAYLOAD_SIZE: u32 = 0x02000000;

///
const RLPX_TRANSPORT_AUTH_ACK_PACKET_SIZE_V4: usize = 210;

//pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;
pub type ProtocolId = [u8; 3];

pub struct CapabilityInfo {
    pub protocol: ProtocolId,
    pub version: u8,
    pub packet_count: u8,
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

    // Imaginary commands from ethereum protocol messages.
    pub const HELLO: [u8; 12] = *b"hello\0\0\0\0\0\0\0";
    pub const STATUS: [u8; 12] = *b"status\0\0\0\0\0\0";    
    pub const AUTHACK: [u8;12] = *b"authack\0\0\0\0\0";
}

/// Bitcoin peer-to-peer message with its payload
//#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Message {
    FeeFilter(FeeFilter),
    Other(String),
    Partial(Box<dyn MsgHeader>),
    Ping(Ping),
    Pong(Ping),
    Reject(Reject),
    SendCmpct(SendCmpct),
    Tx(Tx),
    Tx2(Tx2),
    Verack,
    Authack(Vec<u8>), // maybe verack, but without confirmation from our side
    Version(Version),
    NodeKey(NodeKey),
    Hello(Hello),
    Status(Status),
}

impl Message {
    /// Reads a Bitcoin P2P message with its payload from bytes
    ///
    /// It's possible for a message's header to be read but not its payload. In this case, the
    /// return value is not an Error but a Partial message, and the complete message may be read
    /// later using read_partial.
    pub fn read(reader: &mut dyn Read, magic: [u8; 4], ctx: &mut dyn Ctx) -> Result<Self> {
        let header = MessageHeader::read(reader, ctx)?;
        header.validate(magic, MAX_PAYLOAD_SIZE)?;
        match Message::read_partial(reader, &header, ctx) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                if let Error::IOError(ref e) = e {
                    // Depending on platform, either TimedOut or WouldBlock may be returned to indicate a non-error timeout
                    if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
                    {
                        return Ok(Message::Partial(Box::new(header)));
                    }
                }
                return Err(e);
            }
        }
    }

    pub fn read2(reader: &mut dyn Read, _magic: [u8; 3], ctx: &mut dyn Ctx) -> Result<Self> {
        debug!("expected: {:?}", ctx.expected());
        if commands::AUTHACK == ctx.expected() {
            let mut authack: Vec<u8> = vec![0u8; RLPX_TRANSPORT_AUTH_ACK_PACKET_SIZE_V4];
	        reader.read_exact(authack.as_mut_slice()).unwrap();

            Ok(Message::Authack(authack))
        } else {
            let mut header = SecHeader::read(reader, ctx)?;
            header.command = ctx.expected();
            //header.validate(magic, MAX_PAYLOAD_SIZE)?;
            match Message::read_partial(reader, &header, ctx) {
                Ok(msg) => Ok(msg),
                Err(e) => {
                    if let Error::IOError(ref e) = e {
                        // Depending on platform, either TimedOut or WouldBlock may be returned to indicate a non-error timeout
                        if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
                        {
                            return Ok(Message::Partial(Box::new(header)));
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Reads the complete message given a message header
    ///
    /// It may be used after read() returns Message::Partial.
    pub fn read_partial(reader: &mut dyn Read, header: &dyn MsgHeader, ctx: &mut dyn Ctx) -> Result<Self> {
        // Ping
        if header.command() == commands::PING {
            let payload = header.payload(reader, ctx)?;
            let ping = Ping::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Ping(ping));
        }

        // Pong
        if header.command() == commands::PONG {
            let payload = header.payload(reader, ctx)?;
            let pong = Ping::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Pong(pong));
        }

        // Reject
        if header.command() == commands::REJECT {
            let payload = header.payload(reader, ctx)?;
            let reject = Reject::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Reject(reject));
        }

        // Sendcmpct
        if header.command() == commands::SENDCMPCT {
            let payload = header.payload(reader, ctx)?;
            let sendcmpct = SendCmpct::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::SendCmpct(sendcmpct));
        }

        // Feefilter
        if header.command() == commands::FEEFILTER {
            let payload = header.payload(reader, ctx)?;
            let feefilter = FeeFilter::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::FeeFilter(feefilter));
        }

        // Tx
        if header.command() == commands::TX {
            let payload = header.payload(reader, ctx)?;
            let tx = Tx::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Tx(tx));
        }

        // Version
        if header.command() == commands::VERSION {
            let payload = header.payload(reader, ctx)?;
            let version = Version::read(&mut Cursor::new(payload), ctx)?;
            version.validate()?;
            return Ok(Message::Version(version));
        }
        
        // Hello
        if header.command() == commands::HELLO {
            let payload = header.payload(reader, ctx)?;
            let hello = Hello::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Hello(hello));
        }

        // Status 
        if header.command() == commands::STATUS {
            let payload = header.payload(reader, ctx)?;
            let status = Status::read(&mut Cursor::new(payload), ctx)?;
            return Ok(Message::Status(status));
        }

        // Verack
        if header.command() == commands::VERACK {
            if header.payload_size() != 0 {
                return Err(Error::BadData("Bad payload".to_string()));
            }
            return Ok(Message::Verack);
        }

        if header.command() == commands::AUTHACK {
            panic!("auth ack doesn't supposed to be partially read");
        }

        // Unknown message
        if header.payload_size() > 0 {
            header.payload(reader, ctx)?;
        }
        let command = String::from_utf8(header.command().to_vec()).unwrap_or("Unknown".to_string());
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
            Message::Ping(p)     => write_with_payload(writer, PING, p, magic),
            Message::Pong(p)     => write_with_payload(writer, PONG, p, magic),
            Message::Reject(p)   => write_with_payload(writer, REJECT, p, magic),
            Message::FeeFilter(p)=> write_with_payload(writer, FEEFILTER, p, magic),
            Message::SendCmpct(p)=> write_with_payload(writer, SENDCMPCT, p, magic),
            Message::Tx(p)       => write_with_payload(writer, TX, p, magic),            
            Message::Verack      => write_without_payload(writer, VERACK, magic, ctx),
            Message::Authack(_d) => panic!("we shouldn't confirm the auth, remote side should"),
            Message::Version(v)  => write_with_payload(writer, VERSION, v, magic),
            Message::NodeKey(v)  => write_without_header(writer, v, ctx),
            Message::Tx2(p)      => write_with_payload2(writer, TX, p, magic[..3].try_into().expect("shortened magic"), ctx),
            Message::Hello(h)    => write_with_payload2(writer, HELLO, h, magic[..3].try_into().expect("shortened magic"), ctx),
            Message::Status(s)   => write_with_payload2(writer, STATUS,s, magic[..3].try_into().expect("shortened magic"), ctx),
        }
    }
}

impl fmt::Debug for dyn MsgHeader + 'static {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MsgHdr")
            .field("command", &self.command())
            .finish()
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
            Message::Tx2(_p) => f.write_str(&format!("{:#?}", "merge txs!")),
            Message::Verack => f.write_str("Verack"),
            Message::Authack(_d) => f.write_str("Authack"),
            Message::Version(p) => f.write_str(&format!("{:#?}", p)),
            Message::NodeKey(v) => f.write_str(&format!("{:#?}", v)),
            Message::Hello(h) => f.write_str(&format!("{:#?}", h)),
            Message::Status(s) => f.write_str(&format!("{:#?}", s)),
        }
    }
}

fn write_without_header<T:Serializable<T>>(
    writer: &mut dyn Write,
    payload: &dyn Payload<T>,
    ctx: &mut dyn Ctx,
) -> io::Result<()>{
    payload.write(writer, ctx)
}

fn write_without_payload(
    writer: &mut dyn Write,
    command: [u8; 12],
    magic: [u8; 4],
    ctx: &mut dyn Ctx,
) -> io::Result<()> {
    let header = MessageHeader {
        magic,
        command,
        payload_size: 0,
        checksum: NO_CHECKSUM,
    };
    header.write(writer, ctx)
}

fn write_with_payload2<T:Serializable<T>>(
    writer: &mut dyn Write,
    command: [u8; 12],
    payload: &dyn Payload<T>,
    magic: [u8; 3],
    ctx: &mut dyn Ctx,
) -> io::Result<()>{
    debug!("  cmd: {:?}", command);
    debug!("magic: {:?}", magic);
    debug!(" size: {:?}", payload.size());

    let header = SecHeader{
        magic,
        command, 
        payload_size: payload.size() as u32,
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
