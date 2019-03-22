use ofp_header::{OfpHeader, Xid, OPENFLOW_0_01_VERSION};
use bytes::BytesMut;
use message::Message;
use ofp_message::OfpParsingError;

pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpParsingError> {
    match header.version() {
        OPENFLOW_0_01_VERSION => {
            openflow0x01::parse(header, body)
        },
        v => {
            Err(OfpParsingError::UnsupportedVersion{version: v})
        }
    }
}

pub fn marshal(_version: u8, xid: Xid, message: Message) -> Vec<u8> {
    openflow0x01::marshal(xid, message)
}

pub mod openflow0x01 {
    use message::Message;
    use bytes::BytesMut;
    use ofp_header::OfpHeader;
    use ofp_message::OfpParsingError;
    use ofp_message::OfpMessage;
    use ofp_header::Xid;

    pub fn marshal(xid: Xid, message: Message) -> Vec<u8> {
        Message::marshal(xid, message)
    }

    pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpParsingError> {
        Message::parse(header, body)
    }
}