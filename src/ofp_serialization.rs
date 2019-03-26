use ofp_header::{OfpHeader, Xid, OPENFLOW_0_01_VERSION};
use bytes::BytesMut;
use message::Message;
use ofp_message::OfpParsingError;
use openflow::MsgCode;

pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpParsingError> {
    match header.version() {
        OPENFLOW_0_01_VERSION => {
            openflow0x01::parse(header, body)
        },
        v => {
            if header.type_code() == MsgCode::Hello {
                openflow0x01::parse(header, body)
            } else {
                Err(OfpParsingError::UnsupportedVersion { version: v })
            }
        }
    }
}

pub fn marshal(version: u8, xid: Xid, message: Message) -> Vec<u8> {
    match version {
        OPENFLOW_0_01_VERSION => {
            openflow0x01::marshal(xid, message)
        },
        v => {
            // TODO return a result from here
            warn!("Unsupported OF version {}", v);
            vec!()
        }
    }
}

pub mod openflow0x01 {
    use super::*;
    use ofp_message::OfpMessage;
    use openflow0x01::message::Message0x01;

    pub fn marshal(xid: Xid, message: Message) -> Vec<u8> {
        Message0x01::marshal(xid, Message0x01::from(message))
    }

    pub fn parse(header: &OfpHeader, body: &BytesMut) -> Result<(u32, Message), OfpParsingError> {
        Message0x01::parse(header, body).map(|x| (x.0, x.1.message()))
    }
}