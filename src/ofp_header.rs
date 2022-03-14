use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::mem::{size_of, transmute};

use rust_ofp::openflow::MsgCode;

pub const OFP_HEADER_LENGTH: usize = 8;

pub type Xid = u32;

pub const OPENFLOW_0_01_VERSION: u8 = 1; // 1.0
pub const OPENFLOW_0_04_VERSION: u8 = 4; // 1.3

/// OpenFlow Header
///
/// The first fields of every OpenFlow message, no matter the protocol version.
/// This is parsed to determine version and length of the remaining message, so that
/// it can be properly handled.
#[repr(packed)]
pub struct OfpHeader {
    version: u8,
    typ: u8,
    length: u16,
    xid: u32,
}

impl OfpHeader {
    /// Create an `OfpHeader` out of the arguments.
    pub fn new(version: u8, typ: u8, length: u16, xid: u32) -> OfpHeader {
        OfpHeader {
            version,
            typ,
            length,
            xid,
        }
    }

    /// Return the byte-size of an `OfpHeader`.
    pub fn size() -> usize {
        size_of::<OfpHeader>()
    }

    /// Fills a message buffer with the header fields of an `OfpHeader`.
    pub fn marshal(bytes: &mut Vec<u8>, header: OfpHeader) {
        bytes.write_u8(header.version()).unwrap();
        bytes.write_u8(header.type_code() as u8).unwrap();
        bytes
            .write_u16::<BigEndian>(header.length() as u16)
            .unwrap();
        bytes.write_u32::<BigEndian>(header.xid()).unwrap();
    }

    /// Takes a message buffer (sized for an `OfpHeader`) and returns an `OfpHeader`.
    pub fn parse(buf: &[u8]) -> Self {
        // TODO double check this doesn't do a memcpy
        let mut bytes = Cursor::new(buf);
        OfpHeader::parse_from_cursor(&mut bytes)
    }

    pub fn parse_from_cursor(bytes: &mut Cursor<&[u8]>) -> Self {
        OfpHeader {
            version: bytes.read_u8().unwrap(),
            typ: bytes.read_u8().unwrap(),
            length: bytes.read_u16::<BigEndian>().unwrap(),
            xid: bytes.read_u32::<BigEndian>().unwrap(),
        }
    }

    /// Return the `version` field of a header.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Return the OpenFlow message type code of a header.
    /// # Safety
    ///
    /// The `typ` field of the `self` header is expected to be a `u8` within the
    /// defined range of the `MsgCode` enum.
    pub fn type_code(&self) -> MsgCode {
        unsafe { transmute(self.typ) }
    }

    /// Return the `length` field of a header. Includes the length of the header itself.
    pub fn length(&self) -> usize {
        self.length as usize
    }

    /// Return the `xid` field of a header, the transaction id associated with this packet.
    ///  Replies use the same id to facilitate pairing.
    pub fn xid(&self) -> u32 {
        self.xid
    }
}
