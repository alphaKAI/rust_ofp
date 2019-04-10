use ofp_header::{OfpHeader, Xid, OPENFLOW_0_01_VERSION, OPENFLOW_0_04_VERSION};
use bytes::BytesMut;
use message::Message;
use ofp_message::OfpSerializationError;
use openflow::MsgCode;

pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpSerializationError> {
    match header.version() {
        OPENFLOW_0_01_VERSION => {
            openflow0x01::parse(header, body)
        },
        OPENFLOW_0_04_VERSION => {
            openflow0x04::parse(header, body)
        },
        v => {
            if header.type_code() == MsgCode::Hello {
                openflow0x04::parse(header, body)
            } else {
                Err(OfpSerializationError::UnsupportedVersion { version: v })
            }
        }
    }
}

pub fn marshal(version: u8, xid: Xid, message: Message) -> Result<Vec<u8>, OfpSerializationError> {
    match version {
        OPENFLOW_0_01_VERSION => {
            openflow0x01::marshal(xid, message)
        },
        OPENFLOW_0_04_VERSION => {
            openflow0x04::marshal(xid, message)
        },
        v => {
            Err(OfpSerializationError::UnsupportedVersion {version: v})
        }
    }
}

pub mod openflow0x01 {
    use super::*;
    use ofp_message::OfpMessage;
    use openflow0x01::message::Message0x01;

    pub fn marshal(xid: Xid, message: Message) -> Result<Vec<u8>, OfpSerializationError> {
        Message0x01::marshal(xid, Message0x01::from(message))
    }

    pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpSerializationError> {
        Message0x01::parse(header, body).map(|x| (x.0, x.1.message()))
    }
}

pub mod openflow0x04 {
    use super::*;
    use ofp_message::OfpMessage;
    use openflow0x04::message::Message0x04;

    pub fn marshal(xid: Xid, message: Message) -> Result<Vec<u8>, OfpSerializationError> {
        Message0x04::marshal(xid, Message0x04::from(message))
    }

    pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpSerializationError> {
        Message0x04::parse(header, body).map(|x| (x.0, x.1.message()))
    }
}