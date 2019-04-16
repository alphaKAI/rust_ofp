use std::io::{BufRead, Cursor, Read, Write};
use std::mem::{size_of, transmute};
use bytes::Buf;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use bits::*;
use packet::mac_of_bytes;

use message::*;
use ofp_message::OfpSerializationError;
use ofp_utils::{read_fixed_size_string, write_padding_bytes};
use ofp_header::OPENFLOW_0_04_VERSION;

pub const ALL_TABLES: u8 = 0xff;

/// Common API for message types implementing OpenFlow Message Codes (see `MsgCode` enum).
pub trait MessageType {
    /// Return the byte-size of a message.
    fn size_of(&Self) -> usize;
    /// Parse a buffer into a message.
    fn parse(buf: &[u8]) -> Result<Self, OfpSerializationError> where Self: Sized;
    /// Marshal a message into a `u8` buffer.
    fn marshal(Self, &mut Vec<u8>) -> Result<(), OfpSerializationError>;
}

#[repr(u32)]
pub enum OfpPort {
    OFPPMax = 0xffffff00,
    OFPPInPort = 0xfffffff8,
    OFPPTable = 0xfffffff9,
    OFPPNormal = 0xfffffffa,
    OFPPFlood = 0xfffffffb,
    OFPPAll = 0xfffffffc,
    OFPPController = 0xfffffffd,
    OFPPLocal = 0xfffffffe,
    OFPPNone = 0xffffffff,
}

create_empty_wrapper!(PseudoPort, PseudoPort0x04);

impl PseudoPort0x04 {

    fn make(p: u32, len: u64) -> Result<PseudoPort, OfpSerializationError> {
        let res = match p {
            p if p == (OfpPort::OFPPInPort as u32) => PseudoPort::InPort,
            p if p == (OfpPort::OFPPTable as u32) => PseudoPort::Table,
            p if p == (OfpPort::OFPPNormal as u32) => PseudoPort::Normal,
            p if p == (OfpPort::OFPPFlood as u32) => PseudoPort::Flood,
            p if p == (OfpPort::OFPPAll as u32) => PseudoPort::AllPorts,
            p if p == (OfpPort::OFPPController as u32) => PseudoPort::Controller(len),
            p if p == (OfpPort::OFPPLocal as u32) => PseudoPort::Local,
            _ => {
                if p <= (OfpPort::OFPPMax as u32) {
                    PseudoPort::PhysicalPort(p)
                } else {
                    return Err(OfpSerializationError::UnexpectedValueError {
                        value: format!("{:x}", p),
                        field: "port number".to_string(),
                        message: "".to_string()
                    });
                }
            }
        };

        Ok(res)
    }

    fn marshal(pp: PseudoPort, bytes: &mut Vec<u8>) {
        match pp {
            PseudoPort::PhysicalPort(p) => bytes.write_u32::<BigEndian>(p).unwrap(),
            PseudoPort::InPort => bytes.write_u32::<BigEndian>(OfpPort::OFPPInPort as u32).unwrap(),
            PseudoPort::Table => bytes.write_u32::<BigEndian>(OfpPort::OFPPTable as u32).unwrap(),
            PseudoPort::Normal => bytes.write_u32::<BigEndian>(OfpPort::OFPPNormal as u32).unwrap(),
            PseudoPort::Flood => bytes.write_u32::<BigEndian>(OfpPort::OFPPFlood as u32).unwrap(),
            PseudoPort::AllPorts => bytes.write_u32::<BigEndian>(OfpPort::OFPPAll as u32).unwrap(),
            PseudoPort::Controller(_) => {
                bytes.write_u32::<BigEndian>(OfpPort::OFPPController as u32).unwrap()
            }
            PseudoPort::Local => bytes.write_u32::<BigEndian>(OfpPort::OFPPLocal as u32).unwrap(),
        }
    }
}

#[repr(packed)]
struct OfpActionHeader(u16, u16);

#[repr(packed)]
struct OfpActionOutput(u32, u16, u8, u8, u8, u8, u8, u8);

#[repr(packed)]
struct OfpActionGroup(u32);

#[repr(u16)]
enum OfpActionType {
    OFPATOutput = 0,
    OFPATCopyTtlOut = 11,
    OFPATCopyTtlIn = 12,
    OFPATSetMplsTtl = 15,
    OFPATDecMplsTtl = 16,
    OFPATPushVlan = 17,
    OFPATPopVlan = 18,
    OFPATPushMpls = 19,
    OFPATPopMpls = 20,
    OFPATSetQueue = 21,
    OFPATGroup = 22,
    OFPATSetNwTtl = 23,
    OFPATDecNwTtl = 24,
    OFPATSetField = 25,
    OFPATPushPbb = 26,
    OFPATPopPbb = 27
}

create_empty_wrapper!(Action, Action0x04);

impl Action0x04 {
    fn type_code(a: &Action) -> Result<OfpActionType, OfpSerializationError> {
        match *a {
            Action::Output(_) => Ok(OfpActionType::OFPATOutput),
            Action::Group(_) => Ok(OfpActionType::OFPATGroup),

            unmatched => {
                Err(OfpSerializationError::UnimplementedFeatureInVersion {
                    version: OPENFLOW_0_04_VERSION,
                    feature: String::from(format!("Action {}", unmatched))
                })
            }
        }
    }

    fn size_of(a: &Action) -> usize {
        let h = size_of::<OfpActionHeader>();
        let body = match *a {
            Action::Output(_) => size_of::<OfpActionOutput>(),
            Action::Group(_) => size_of::<OfpActionGroup>(),
            _ => 0,
        };
        h + body
    }

    fn size_of_sequence(actions: &Vec<Action>) -> usize {
        actions.iter().fold(0, |acc, x| Action0x04::size_of(x) + acc)
    }

    fn _parse(bytes: &mut Cursor<Vec<u8>>) -> Result<Action, OfpSerializationError> {
        let action_code = bytes.read_u16::<BigEndian>().unwrap();
        let _ = bytes.read_u16::<BigEndian>().unwrap();
        let action = match action_code {
            t if t == (OfpActionType::OFPATOutput as u16) => {
                let port_code = bytes.read_u32::<BigEndian>().unwrap();
                let len = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(6);
                Action::Output(PseudoPort0x04::make(port_code, len as u64)?)
            },
            t if t == (OfpActionType::OFPATGroup as u16) => {
                let group_id = GroupId(bytes.read_u32::<BigEndian>().unwrap());

                Action::Group(group_id)
            }
            code => {
                return Err(OfpSerializationError::UnimplementedFeatureInVersion {
                    version: OPENFLOW_0_04_VERSION,
                    feature: String::from(format!("Action code {} parsing", code))
                })
            }
        };
        Ok(action)
    }

    fn parse_sequence(bytes: &mut Cursor<Vec<u8>>) -> Result<Vec<Action>, OfpSerializationError> {
        if bytes.remaining() == 0 {
            Ok(vec![])
        } else {
            let action = Action0x04::_parse(bytes)?;
            let mut v = vec![action];
            v.append(&mut Action0x04::parse_sequence(bytes)?);
            Ok(v)
        }
    }

    fn move_controller_last(acts: Vec<Action>) -> Vec<Action> {
        let (mut to_ctrl, mut not_to_ctrl): (Vec<Action>, Vec<Action>) = acts.into_iter()
            .partition(|act| match *act {
                Action::Output(PseudoPort::Controller(_)) => true,
                _ => false,
            });
        not_to_ctrl.append(&mut to_ctrl);
        not_to_ctrl
    }

    fn marshal(act: Action, bytes: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        bytes.write_u16::<BigEndian>(Action0x04::type_code(&act)? as u16).unwrap();
        bytes.write_u16::<BigEndian>(Action0x04::size_of(&act) as u16).unwrap();
        match act {
            Action::Output(pp) => {
                PseudoPort0x04::marshal(pp, bytes);
                bytes.write_u32::<BigEndian>(match pp {
                    PseudoPort::Controller(w) => w as u32,
                    _ => 0,
                }).unwrap();
                write_padding_bytes(bytes, 6);
            },
            Action::Group(group_id) => {
                bytes.write_u32::<BigEndian>(group_id.id()).unwrap();
            }
            code => {
                return Err(OfpSerializationError::UnimplementedFeatureInVersion {
                    version: OPENFLOW_0_04_VERSION,
                    feature: String::from(format!("Action code {} marshaling", code))
                })
            }
        }

        Ok(())
    }
}

#[repr(packed)]
struct OfpSwitchFeatures(u64, u32, u8, [u8; 3], u32, u32);

impl MessageType for SwitchFeatures {
    fn size_of(sf: &SwitchFeatures) -> usize {
        // TODO same code as 1.0 (refactor)
        let pds: usize = match &sf.ports {
            Some(ports) => {
                ports.iter().map(|pd| PortDesc0x04::size_of(pd)).sum()
            },
            None => 0
        };
        size_of::<OfpSwitchFeatures>() + pds
    }

    fn parse(buf: &[u8]) -> Result<SwitchFeatures, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let datapath_id = bytes.read_u64::<BigEndian>().unwrap();
        let num_buffers = bytes.read_u32::<BigEndian>().unwrap();
        let num_tables = bytes.read_u8().unwrap();
        let auxiliary_id = bytes.read_u8().unwrap();
        bytes.consume(2);
        let supported_capabilities = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            let port_blocked = test_bit(8, d as u64);
            Capabilities {
                flow_stats: test_bit(0, d as u64),
                table_stats: test_bit(1, d as u64),
                port_stats: test_bit(2, d as u64),
                group_stats: test_bit(3, d as u64),
                ip_reasm: test_bit(5, d as u64),
                queue_stats: test_bit(6, d as u64),
                port_blocked,
                arp_match_ip: true,
                stp: port_blocked
            }
        };
        bytes.consume(4);
        Ok(SwitchFeatures {
            datapath_id,
            num_buffers,
            num_tables,
            auxiliary_id,
            supported_capabilities,
            supported_actions: None,
            ports: None,
        })
    }

    fn marshal(_: SwitchFeatures, _: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        Err(OfpSerializationError::UnimplementedFeatureInVersion {
            version: OPENFLOW_0_04_VERSION,
            feature: String::from("Marshaling SwitchFeatures")
        })
    }
}

#[repr(u32)]
pub enum OfpQueue {
    OFPQAll = 0xffffffff,
}

create_empty_wrapper!(Payload, Payload0x04);

impl Payload0x04 {
    fn marshal(payload: Payload, bytes: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        match payload {
            Payload::Buffered(_, buf) |
            Payload::NotBuffered(buf) => bytes.write_all(&buf),
        }.map_err(|e| OfpSerializationError::IoError {
            error: e
        })
    }
}

#[repr(packed)]
struct OfpPacketIn(i32, u16, u16, u8, u8);

impl MessageType for PacketIn {
    fn size_of(pi: &PacketIn) -> usize {
        size_of::<OfpPacketIn>() + Payload::size_of(&pi.input_payload)
    }

    fn parse(buf: &[u8]) -> Result<PacketIn, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let buf_id = match bytes.read_i32::<BigEndian>().unwrap() {
            -1 => None,
            n => Some(n),
        };
        let total_len = bytes.read_u16::<BigEndian>().unwrap();
        let port = bytes.read_u32::<BigEndian>().unwrap();
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(1);
        let pk = bytes.fill_buf().unwrap().to_vec();
        let payload = match buf_id {
            None => Payload::NotBuffered(pk),
            Some(n) => Payload::Buffered(n as u32, pk),
        };
        Ok(PacketIn {
            input_payload: payload,
            total_len: total_len,
            port: port,
            reason: reason,
        })
    }

    fn marshal(pi: PacketIn, bytes: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        let buf_id = match pi.input_payload {
            Payload::NotBuffered(_) => -1,
            Payload::Buffered(n, _) => n as i32,
        };
        bytes.write_i32::<BigEndian>(buf_id).unwrap();
        bytes.write_u16::<BigEndian>(pi.total_len).unwrap();
        bytes.write_u32::<BigEndian>(pi.port).unwrap();
        bytes.write_u8(pi.reason as u8).unwrap();
        bytes.write_u8(0).unwrap(); // Padding
        Payload0x04::marshal(pi.input_payload, bytes)
    }
}

#[repr(packed)]
struct OfpPacketOut(u32, u16, u16);

impl MessageType for PacketOut {
    fn size_of(po: &PacketOut) -> usize {
        size_of::<OfpPacketOut>() + Action0x04::size_of_sequence(&po.apply_actions) +
        Payload::size_of(&po.output_payload)
    }

    fn parse(buf: &[u8]) -> Result<PacketOut, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let buf_id = match bytes.read_i32::<BigEndian>().unwrap() {
            -1 => None,
            n => Some(n),
        };
        let in_port = bytes.read_u32::<BigEndian>().unwrap();
        let actions_len = bytes.read_u16::<BigEndian>().unwrap();
        bytes.consume(6);
        let mut actions_buf = vec![0; actions_len as usize];
        bytes.read_exact(&mut actions_buf).unwrap();
        let mut actions_bytes = Cursor::new(actions_buf);
        let actions = Action0x04::parse_sequence(&mut actions_bytes)?;
        Ok(PacketOut {
            output_payload: match buf_id {
                None => Payload::NotBuffered(bytes.fill_buf().unwrap().to_vec()),
                Some(n) => Payload::Buffered(n as u32, bytes.fill_buf().unwrap().to_vec()),
            },
            port_id: {
                if in_port == OfpPort::OFPPNone as u32 {
                    None
                } else {
                    Some(in_port)
                }
            },
            apply_actions: actions,
        })
    }

    fn marshal(po: PacketOut, bytes: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        bytes.write_i32::<BigEndian>(match po.output_payload {
                Payload::Buffered(n, _) => n as i32,
                Payload::NotBuffered(_) => -1,
            })
            .unwrap();
        match po.port_id {
            Some(id) => PseudoPort0x04::marshal(PseudoPort::PhysicalPort(id), bytes),
            None => bytes.write_u32::<BigEndian>(OfpPort::OFPPNone as u32).unwrap(),
        }
        bytes.write_u16::<BigEndian>(Action0x04::size_of_sequence(&po.apply_actions) as u16).unwrap();
        write_padding_bytes(bytes, 6);
        for act in Action0x04::move_controller_last(po.apply_actions) {
            // TODO check for valid PacketOut actions
            Action0x04::marshal(act, bytes)?;
        }
        Payload0x04::marshal(po.output_payload, bytes)
    }
}

create_empty_wrapper!(PortFeatures, PortFeatures0x04);

impl PortFeatures0x04 {
    fn of_int(d: u32) -> PortFeatures {
        PortFeatures {
            f_10mbhd: test_bit(0, d as u64),
            f_10mbfd: test_bit(1, d as u64),
            f_100mbhd: test_bit(2, d as u64),
            f_100mbfd: test_bit(3, d as u64),
            f_1gbhd: test_bit(4, d as u64),
            f_1gbfd: test_bit(5, d as u64),
            f_10gbfd: test_bit(6, d as u64),
            copper: test_bit(7, d as u64),
            fiber: test_bit(8, d as u64),
            autoneg: test_bit(9, d as u64),
            pause: test_bit(10, d as u64),
            pause_asym: test_bit(11, d as u64),
        }
    }
}

#[repr(packed)]
struct OfpPhyPort(u16, [u8; 6], [u8; 16], u32, u32, u32, u32, u32, u32);

create_empty_wrapper!(PortDesc, PortDesc0x04);

impl PortDesc0x04 {
    fn size_of(_: &PortDesc) -> usize {
        size_of::<OfpPhyPort>()
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Result<PortDesc, OfpSerializationError> {
        let port_no = bytes.read_u16::<BigEndian>().unwrap();
        let hw_addr = {
            let mut arr: [u8; 6] = [0; 6];
            for i in 0..6 {
                arr[i] = bytes.read_u8().unwrap();
            }
            mac_of_bytes(arr)
        };
        let name = read_fixed_size_string(bytes, 16);
        let config = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            PortConfig {
                down: test_bit(0, d as u64),
                no_stp: test_bit(1, d as u64),
                no_recv: test_bit(2, d as u64),
                no_recv_stp: test_bit(3, d as u64),
                no_flood: test_bit(4, d as u64),
                no_fwd: test_bit(5, d as u64),
                no_packet_in: test_bit(6, d as u64),
            }
        };
        let state = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            PortState {
                down: test_bit(0, d as u64),
                stp_state: {
                    let mask: u32 = 3 << 8;
                    let d_masked = d & mask;
                    if d_masked == (StpState::Listen as u32) << 8 {
                        StpState::Listen
                    } else if d_masked == (StpState::Learn as u32) << 8 {
                        StpState::Learn
                    } else if d_masked == (StpState::Forward as u32) << 8 {
                        StpState::Forward
                    } else if d_masked == (StpState::Block as u32) << 8 {
                        StpState::Block
                    } else {
                        return Err(
                            OfpSerializationError::UnexpectedValueError {
                                value: format!("{:x}", d_masked),
                                field: "ofp_port_state/stp_state".to_string(),
                                message: "Port Description".to_string(),
                            }
                        );
                    }
                },
            }
        };
        let curr = PortFeatures0x04::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let advertised = PortFeatures0x04::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let supported = PortFeatures0x04::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let peer = PortFeatures0x04::of_int(bytes.read_u32::<BigEndian>().unwrap());
        Ok(PortDesc {
            port_no: port_no,
            hw_addr: hw_addr,
            name: name,
            config: config,
            state: state,
            curr: curr,
            advertised: advertised,
            supported: supported,
            peer: peer,
        })
    }
}

impl MessageType for PortStatus {
    fn size_of(_: &PortStatus) -> usize {
        size_of::<PortReason>() + size_of::<OfpPhyPort>()
    }

    fn parse(buf: &[u8]) -> Result<PortStatus, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(7);
        let desc = PortDesc0x04::parse(&mut bytes)?;
        Ok(PortStatus {
            reason: reason,
            desc: desc,
        })
    }

    fn marshal(_: PortStatus, _: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        Err(OfpSerializationError::UnimplementedFeatureInVersion {
            version: OPENFLOW_0_04_VERSION,
            feature: String::from("Marshaling PortStatus")
        })
    }
}

#[repr(packed)]
struct OfpErrorMsg(u16, u16);

impl MessageType for Error {
    fn size_of(err: &Error) -> usize {
        match *err {
            Error::Error(_, ref body) => size_of::<OfpErrorMsg>() + body.len(),
        }
    }

    fn parse(buf: &[u8]) -> Result<Error, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let error_type = bytes.read_u16::<BigEndian>().unwrap();
        let error_code = bytes.read_u16::<BigEndian>().unwrap();
        let code = match error_type {
            0 => ErrorType::HelloFailed(unsafe { transmute(error_code) }),
            1 => ErrorType::BadRequest(unsafe { transmute(error_code) }),
            2 => ErrorType::BadAction(unsafe { transmute(error_code) }),
            3 => ErrorType::FlowModFailed(unsafe { transmute(error_code) }),
            4 => ErrorType::PortModFailed(unsafe { transmute(error_code) }),
            5 => ErrorType::QueueOpFailed(unsafe { transmute(error_code) }),
            _ => {
                return Err(OfpSerializationError::UnexpectedValueError {
                    value: format!("{:x}", error_type),
                    field: "error type".to_string(),
                    message: "error".to_string()
                });
            }
        };
        Ok(Error::Error(code, bytes.fill_buf().unwrap().to_vec()))
    }

    fn marshal(_: Error, _: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
        Err(OfpSerializationError::UnimplementedFeatureInVersion {
            version: OPENFLOW_0_04_VERSION,
            feature: String::from("Marshaling Error")
        })
    }
}

/// Encapsulates handling of messages implementing `MessageType` trait.
pub mod message {
    use super::*;
    use std::io::Write;
    use ofp_header::{OfpHeader, OPENFLOW_0_04_VERSION};
    use ofp_message::{OfpMessage, OfpSerializationError};
    use openflow::MsgCode;

    pub struct Message0x04 {
        inner: Message
    }

    impl From<Message> for Message0x04 {
        fn from(m: Message) -> Self {
            Message0x04 { inner: m }
        }
    }

    impl Message0x04 {

        pub fn message(self) -> Message {
            self.inner
        }

        /// Map `Message` to associated OpenFlow message type code `MsgCode`.
        fn msg_code_of_message(msg: &Message) -> MsgCode {
            match *msg {
                Message::Hello => MsgCode::Hello,
                Message::Error(_) => MsgCode::Error,
                Message::EchoRequest(_) => MsgCode::EchoReq,
                Message::EchoReply(_) => MsgCode::EchoResp,
                Message::FeaturesReq => MsgCode::FeaturesReq,
                Message::FeaturesReply(_) => MsgCode::FeaturesResp,
                Message::FlowMod(_) => MsgCode::FlowMod,
                Message::PacketIn(_) => MsgCode::PacketIn,
                Message::FlowRemoved(_) => MsgCode::FlowRemoved,
                Message::PortStatus(_) => MsgCode::PortStatus,
                Message::PacketOut(_) => MsgCode::PacketOut,
                Message::BarrierRequest => MsgCode::BarrierReq,
                Message::BarrierReply => MsgCode::BarrierResp,
                Message::StatsRequest(_) => MsgCode::MultipartReq,
                Message::StatsReply(_) => MsgCode::MultipartResp,
            }
        }

        fn msg_code_to_u8(msgcode: &MsgCode) -> Result<u8, OfpSerializationError> {
            match msgcode {
                MsgCode::Hello => Ok(0),
                MsgCode::Error => Ok(1),
                MsgCode::EchoReq => Ok(2),
                MsgCode::EchoResp => Ok(3),
                MsgCode::Experimenter => Ok(4),
                MsgCode::FeaturesReq => Ok(5),
                MsgCode::FeaturesResp => Ok(6),
                MsgCode::GetConfigReq => Ok(7),
                MsgCode::GetConfigResp => Ok(8),
                MsgCode::SetConfig => Ok(9),
                MsgCode::PacketIn => Ok(10),
                MsgCode::FlowRemoved => Ok(11),
                MsgCode::PortStatus => Ok(12),
                MsgCode::PacketOut => Ok(13),
                MsgCode::FlowMod => Ok(14),
                MsgCode::GroupMod => Ok(15),
                MsgCode::PortMod => Ok(16),
                MsgCode::TableMod => Ok(17),
                MsgCode::MultipartReq => Ok(18),
                MsgCode::MultipartResp => Ok(19),
                MsgCode::BarrierReq => Ok(20),
                MsgCode::BarrierResp => Ok(21),
                MsgCode::QueueGetConfigReq => Ok(22),
                MsgCode::QueueGetConfigResp => Ok(23),
                MsgCode::RoleReq => Ok(24),
                MsgCode::RoleResp => Ok(25),
                MsgCode::GetAsyncReq => Ok(26),
                MsgCode::GetAsyncResp => Ok(27),
                MsgCode::SetAsync => Ok(28),
                MsgCode::MeterMod => Ok(29),
                c => Err(OfpSerializationError::UnsupportedMessageCode {
                    version: OPENFLOW_0_04_VERSION,
                    code: *c
                })
            }
        }

        fn msg_code_of_message_u8(msg: &Message) -> Result<u8, OfpSerializationError> {
            Self::msg_code_to_u8(&Self::msg_code_of_message(msg))
        }

        /// Marshal the OpenFlow message `msg`.
        fn marshal_body(msg: Message, bytes: &mut Vec<u8>) -> Result<(), OfpSerializationError> {
            match msg {
                Message::Hello => Ok(()),
                Message::Error(buf) => Error::marshal(buf, bytes),
                Message::EchoReply(buf) => OfpSerializationError::from_io_result(bytes.write_all(&buf)),
                Message::EchoRequest(buf) => OfpSerializationError::from_io_result(bytes.write_all(&buf)),
                Message::FeaturesReq => Ok(()),
                Message::PacketIn(packet_in) => PacketIn::marshal(packet_in, bytes),
                Message::PacketOut(po) => PacketOut::marshal(po, bytes),
                Message::BarrierRequest | Message::BarrierReply => Ok(()),
                msg => Err(
                    OfpSerializationError::UnimplementedFeatureInVersion {
                        version: OPENFLOW_0_04_VERSION,
                        feature: String::from(format!("Message {}", Self::msg_code_of_message(&msg)))
                    }
                ),
            }
        }
    }

    impl OfpMessage for Message0x04 {
        fn size_of(msg: &Message0x04) -> Result<usize, OfpSerializationError> {
            match msg.inner {
                Message::Hello => Ok(OfpHeader::size()),
                Message::Error(ref err) => Ok(Error::size_of(err)),
                Message::EchoRequest(ref buf) => Ok(OfpHeader::size() + buf.len()),
                Message::EchoReply(ref buf) => Ok(OfpHeader::size() + buf.len()),
                Message::FeaturesReq => Ok(OfpHeader::size()),
                Message::PacketIn(ref packet_in) => {
                    Ok(OfpHeader::size() + PacketIn::size_of(packet_in))
                }
                Message::PacketOut(ref po) => Ok(OfpHeader::size() + PacketOut::size_of(po)),
                Message::BarrierRequest | Message::BarrierReply => Ok(OfpHeader::size()),

                ref message => Err(OfpSerializationError::UnsupportedMessageCode {
                    version: OPENFLOW_0_04_VERSION,
                    code: Self::msg_code_of_message(&message)
                }),
            }
        }

        fn header_of(xid: u32, msg: &Message0x04) -> Result<OfpHeader, OfpSerializationError> {
            let sizeof_buf = Self::size_of(&msg)?;
            Ok(OfpHeader::new(OPENFLOW_0_04_VERSION,
                           Self::msg_code_of_message_u8(&msg.inner)?,
                           sizeof_buf as u16,
                           xid))
        }

        fn marshal(xid: u32, msg: Message0x04) -> Result<Vec<u8>, OfpSerializationError> {
            let hdr = Self::header_of(xid, &msg)?;
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr);
            Message0x04::marshal_body(msg.inner, &mut bytes)?;
            Ok(bytes)
        }

        fn parse(header: &OfpHeader, buf: &[u8]) -> Result<(u32, Message0x04), OfpSerializationError> {
            let typ = header.type_code();
            let msg = Message0x04 { inner: match typ {
                MsgCode::Hello => {
                    debug!("Message received: Hello!");
                    Message::Hello
                }
                MsgCode::Error => {
                    debug!("Message received: Error");
                    Message::Error(Error::parse(buf)?)
                }
                MsgCode::EchoReq => Message::EchoRequest(buf.to_vec()),
                MsgCode::EchoResp => Message::EchoReply(buf.to_vec()),
                MsgCode::FeaturesResp => {
                    debug!("Message received: FeaturesResp");
                    Message::FeaturesReply(SwitchFeatures::parse(buf)?)
                }
                MsgCode::PacketIn => {
                    debug!("Message received: PacketIn");
                    Message::PacketIn(PacketIn::parse(buf)?)
                }
                MsgCode::PacketOut => {
                    debug!("Message received: PacketOut");
                    Message::PacketOut(PacketOut::parse(buf)?)
                }
                MsgCode::BarrierReq => Message::BarrierRequest,
                MsgCode::BarrierResp => Message::BarrierReply,
                code => return Result::Err(OfpSerializationError::UnexpectedValueError {
                    value: format!("0x{:x}", code as u8),
                    field: "message type".to_string(),
                    message: "message header".to_string()
                }),
            }};
            Ok((header.xid(), msg))
        }
    }

    #[cfg(test)]
    mod tests {
    }
}

#[cfg(test)]
mod tests {
}