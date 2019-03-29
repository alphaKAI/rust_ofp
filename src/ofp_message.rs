use ofp_header::{ OfpHeader, Xid };
use std::io;
use openflow::MsgCode;

#[derive(Debug, Fail)]
pub enum OfpSerializationError {
    #[fail(display = "IO Error: {}", error)]
    IoError {
        error: io::Error,
    },
    #[fail(display = "Unexpected value '{}' at field '{}' of '{}'", value, field, message)]
    UnexpectedValueError {
        value: String,
        field: String,
        message: String,
    },
    #[fail(display = "Parsing error: {}", message)]
    ParsingError {
        message: String,
    },
    #[fail(display = "Unsupported OpenFlow version: {}", version)]
    UnsupportedVersion {
        version: u8
    },
    #[fail(display = "Unsupported OpenFlow message code {} for version: {}", code, version)]
    UnsupportedMessageCode {
        version: u8,
        code: MsgCode
    }
}

/// OpenFlow Message
///
/// Version-agnostic API for handling OpenFlow messages at the byte-buffer level.
pub trait OfpMessage {
    /// Return the byte-size of an `OfpMessage`.
    fn size_of(&Self) -> usize;
    /// Create an `OfpHeader` for the given transaction id and OpenFlow message.
    fn header_of(Xid, &Self) -> Result<OfpHeader, OfpSerializationError>;
    /// Return a marshaled buffer containing an OpenFlow header and the message `msg`.
    fn marshal(Xid, Self) -> Result<Vec<u8>, OfpSerializationError>;
    /// Returns a pair `(u32, OfpMessage)` of the transaction id and OpenFlow message parsed from
    /// the given OpenFlow header `header`, and buffer `buf`.
    fn parse(&OfpHeader, &[u8]) -> Result<(Xid, Self), OfpSerializationError> where Self: Sized;
}
