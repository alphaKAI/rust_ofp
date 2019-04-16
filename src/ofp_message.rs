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
    #[fail(display = "Not implemented OpenFlow version: {}", version)]
    UnsupportedVersion {
        version: u8
    },
    #[fail(display = "Feature unimplemented in OpenFlow {}: {}", version, feature)]
    UnimplementedFeatureInVersion {
        version: u8,
        feature: String,
    },
    #[fail(display = "Unavailable OpenFlow message code {} for version: {}", code, version)]
    UnsupportedMessageCode {
        version: u8,
        code: MsgCode
    },
    #[fail(display = "Unavailable OpenFlow message {} for version: {}", message, version)]
    UnavailableMessageInVersion {
        version: u8,
        message: String
    },
    #[fail(display = "Unavailable OpenFlow feature {} for {} in version: {}", feature, field, version)]
    UnavailableFeatureInVersion {
        version: u8,
        feature: String,
        field: String
    },

}

impl From<io::Error> for OfpSerializationError {
    fn from(e: io::Error) -> Self {
        OfpSerializationError::IoError {
            error: e
        }
    }
}

impl OfpSerializationError {
    pub fn from_io_result(r: io::Result<()>) -> Result<(), OfpSerializationError> {
        r.map_err(|e| OfpSerializationError::from(e))
    }
}

/// OpenFlow Message
///
/// Version-agnostic API for handling OpenFlow messages at the byte-buffer level.
pub trait OfpMessage {
    /// Return the byte-size of an `OfpMessage`.
    fn size_of(&Self) -> Result<usize, OfpSerializationError>;
    /// Create an `OfpHeader` for the given transaction id and OpenFlow message.
    fn header_of(Xid, &Self) -> Result<OfpHeader, OfpSerializationError>;
    /// Return a marshaled buffer containing an OpenFlow header and the message `msg`.
    fn marshal(Xid, Self) -> Result<Vec<u8>, OfpSerializationError>;
    /// Returns a pair `(u32, OfpMessage)` of the transaction id and OpenFlow message parsed from
    /// the given OpenFlow header `header`, and buffer `buf`.
    fn parse(&OfpHeader, &[u8]) -> Result<(Xid, Self), OfpSerializationError> where Self: Sized;
}
