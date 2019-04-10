use std::io;
use std::io::{BufRead, Cursor, Read, Write};
use std::mem::{size_of, transmute};
use bytes::Buf;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use bits::*;
use packet::{bytes_of_mac, mac_of_bytes};

use message::*;
use ofp_message::OfpSerializationError;
use ofp_utils::{write_padding_bytes, read_fixed_size_string};

const OFP_MAX_TABLE_NAME_LENGTH: usize = 32;
const DESC_STR_LENGTH: usize = 256;
const SERIAL_NUM_LENGTH: usize = 32;

pub const ALL_TABLES: u8 = 0xff;
const MAIN_CONNECTION: u8 = 0;

/// Common API for message types implementing OpenFlow Message Codes (see `MsgCode` enum).
pub trait MessageType {
    /// Return the byte-size of a message.
    fn size_of(&Self) -> usize;
    /// Parse a buffer into a message.
    fn parse(buf: &[u8]) -> Result<Self, OfpSerializationError> where Self: Sized;
    /// Marshal a message into a `u8` buffer.
    fn marshal(Self, &mut Vec<u8>);
}

create_empty_wrapper!(Wildcards, Wildcards0x01);

impl Wildcards0x01 {
    fn set_nw_mask(f: u32, offset: usize, v: u32) -> u32 {
        let value = (0x3f & v) << offset;
        f | value
    }

    fn get_nw_mask(f: u32, offset: usize) -> u32 {
        (f >> offset) & 0x3f
    }

    fn marshal(w: Wildcards, bytes: &mut Vec<u8>) {
        let ret = 0u32;
        let ret = bit(0, ret as u64, w.in_port) as u32;
        let ret = bit(1, ret as u64, w.dl_vlan) as u32;
        let ret = bit(2, ret as u64, w.dl_src) as u32;
        let ret = bit(3, ret as u64, w.dl_dst) as u32;
        let ret = bit(4, ret as u64, w.dl_type) as u32;
        let ret = bit(5, ret as u64, w.nw_proto) as u32;
        let ret = bit(6, ret as u64, w.tp_src) as u32;
        let ret = bit(7, ret as u64, w.tp_dst) as u32;
        let ret = Wildcards0x01::set_nw_mask(ret, 8, w.nw_src);
        let ret = Wildcards0x01::set_nw_mask(ret, 14, w.nw_dst);
        let ret = bit(20, ret as u64, w.dl_vlan_pcp) as u32;
        let ret = bit(21, ret as u64, w.nw_tos) as u32;
        bytes.write_u32::<BigEndian>(ret).unwrap()
    }

    fn parse(bits: u32) -> Wildcards {
        Wildcards {
            in_port: test_bit(0, bits as u64),
            dl_vlan: test_bit(1, bits as u64),
            dl_src: test_bit(2, bits as u64),
            dl_dst: test_bit(3, bits as u64),
            dl_type: test_bit(4, bits as u64),
            nw_proto: test_bit(5, bits as u64),
            tp_src: test_bit(6, bits as u64),
            tp_dst: test_bit(7, bits as u64),
            nw_src: Wildcards0x01::get_nw_mask(bits, 8),
            nw_dst: Wildcards0x01::get_nw_mask(bits, 14),
            dl_vlan_pcp: test_bit(20, bits as u64),
            nw_tos: test_bit(21, bits as u64),
        }
    }
}

create_empty_wrapper!(Pattern, Pattern0x01);

impl Pattern0x01 {
    fn size_of(_: &Pattern) -> usize {
        size_of::<OfpMatch>()
    }

    fn parse(bytes: &mut Cursor<Vec<u8>>) -> Pattern {
        let w = Wildcards0x01::parse(bytes.read_u32::<BigEndian>().unwrap());
        let in_port = if w.in_port {
            bytes.consume( 2);
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let dl_src = if w.dl_src {
            bytes.consume(6);
            None
        } else {
            let mut arr: [u8; 6] = [0; 6];
            for i in 0..6 {
                arr[i] = bytes.read_u8().unwrap();
            }
            Some(mac_of_bytes(arr))
        };
        let dl_dst = if w.dl_dst {
            bytes.consume(6);
            None
        } else {
            let mut arr: [u8; 6] = [0; 6];
            for i in 0..6 {
                arr[i] = bytes.read_u8().unwrap();
            }
            Some(mac_of_bytes(arr))
        };
        let dl_vlan = if w.dl_vlan {
            bytes.consume(2);
            None
        } else {
            let vlan = bytes.read_u16::<BigEndian>().unwrap();
            if vlan == 0xfff {
                Some(None)
            } else {
                Some(Some(vlan))
            }
        };
        let dl_vlan_pcp = if w.dl_vlan_pcp {
            bytes.consume(1);
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        bytes.consume(1);
        let dl_typ = if w.dl_type {
            bytes.consume(2);
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let nw_tos = if w.nw_tos {
            bytes.consume(1);
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        let nw_proto = if w.nw_proto {
            bytes.consume(1);
            None
        } else {
            Some(bytes.read_u8().unwrap())
        };
        bytes.consume(2);
        let nw_src = if w.nw_src >= 32 {
            bytes.consume(4);
            None
        } else if w.nw_src == 0 {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: None,
            })
        } else {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: Some(w.nw_src),
            })
        };
        let nw_dst = if w.nw_dst >= 32 {
            bytes.consume(4);
            None
        } else if w.nw_dst == 0 {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: None,
            })
        } else {
            Some(Mask {
                value: bytes.read_u32::<BigEndian>().unwrap(),
                mask: Some(w.nw_dst),
            })
        };
        let tp_src = if w.tp_src {
            bytes.consume(2);
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        let tp_dst = if w.tp_dst {
            bytes.consume(2);
            None
        } else {
            Some(bytes.read_u16::<BigEndian>().unwrap())
        };
        Pattern {
            dl_src: dl_src,
            dl_dst: dl_dst,
            dl_typ: dl_typ,
            dl_vlan: dl_vlan,
            dl_vlan_pcp: dl_vlan_pcp,
            nw_src: nw_src,
            nw_dst: nw_dst,
            nw_proto: nw_proto,
            nw_tos: nw_tos,
            tp_src: tp_src,
            tp_dst: tp_dst,
            in_port: in_port,
        }
    }

    fn if_word48(n: Option<u64>) -> u64 {
        match n {
            Some(n) => n,
            None => 0,
        }
    }

    fn marshal(p: Pattern, bytes: &mut Vec<u8>) {
        let w = Pattern::wildcards_of_pattern(&p);
        Wildcards0x01::marshal(w, bytes);
        bytes.write_u16::<BigEndian>(p.in_port.unwrap_or(0)).unwrap();
        for i in 0..6 {
            bytes.write_u8(bytes_of_mac(Self::if_word48(p.dl_src))[i]).unwrap();
        }
        for i in 0..6 {
            bytes.write_u8(bytes_of_mac(Self::if_word48(p.dl_dst))[i]).unwrap();
        }
        let vlan = match p.dl_vlan {
            Some(Some(v)) => v,
            Some(None) => 0xffff,
            None => 0xffff,
        };
        bytes.write_u16::<BigEndian>(vlan).unwrap();
        bytes.write_u8(p.dl_vlan_pcp.unwrap_or(0)).unwrap();
        bytes.write_u8(0).unwrap();
        bytes.write_u16::<BigEndian>(p.dl_typ.unwrap_or(0)).unwrap();
        bytes.write_u8(p.nw_tos.unwrap_or(0)).unwrap();
        bytes.write_u8(p.nw_proto.unwrap_or(0)).unwrap();
        bytes.write_u16::<BigEndian>(0).unwrap();

        bytes.write_u32::<BigEndian>(p.nw_src
                .unwrap_or(Mask {
                    value: 0,
                    mask: None,
                })
                .value)
            .unwrap();
        bytes.write_u32::<BigEndian>(p.nw_dst
                .unwrap_or(Mask {
                    value: 0,
                    mask: None,
                })
                .value)
            .unwrap();

        bytes.write_u16::<BigEndian>(p.tp_src.unwrap_or(0)).unwrap();
        bytes.write_u16::<BigEndian>(p.tp_dst.unwrap_or(0)).unwrap();
    }
}

#[repr(packed)]
struct OfpMatch(u32, u16, [u8; 6], [u8; 6], u16, u8, u8, u16, u8, u8, u16, u32, u32, u16, u16);

#[repr(u16)]
pub enum OfpPort {
    OFPPMax = 0xff00,
    OFPPInPort = 0xfff8,
    OFPPTable = 0xfff9,
    OFPPNormal = 0xfffa,
    OFPPFlood = 0xfffb,
    OFPPAll = 0xfffc,
    OFPPController = 0xfffd,
    OFPPLocal = 0xfffe,
    OFPPNone = 0xffff,
}


create_empty_wrapper!(PseudoPort, PseudoPort0x01);

impl PseudoPort0x01 {
    fn of_int(p: u16) -> Result<Option<PseudoPort>, OfpSerializationError> {
        if (OfpPort::OFPPNone as u16) == p {
            Ok(None)
        } else {
            Ok(Some(PseudoPort0x01::make(p, 0)?))
        }
    }

    fn make(p: u16, len: u64) -> Result<PseudoPort, OfpSerializationError> {
        let res = match p {
            p if p == (OfpPort::OFPPInPort as u16) => PseudoPort::InPort,
            p if p == (OfpPort::OFPPTable as u16) => PseudoPort::Table,
            p if p == (OfpPort::OFPPNormal as u16) => PseudoPort::Normal,
            p if p == (OfpPort::OFPPFlood as u16) => PseudoPort::Flood,
            p if p == (OfpPort::OFPPAll as u16) => PseudoPort::AllPorts,
            p if p == (OfpPort::OFPPController as u16) => PseudoPort::Controller(len),
            p if p == (OfpPort::OFPPLocal as u16) => PseudoPort::Local,
            _ => {
                if p <= (OfpPort::OFPPMax as u16) {
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
            PseudoPort::PhysicalPort(p) => bytes.write_u16::<BigEndian>(p).unwrap(),
            PseudoPort::InPort => bytes.write_u16::<BigEndian>(OfpPort::OFPPInPort as u16).unwrap(),
            PseudoPort::Table => bytes.write_u16::<BigEndian>(OfpPort::OFPPTable as u16).unwrap(),
            PseudoPort::Normal => bytes.write_u16::<BigEndian>(OfpPort::OFPPNormal as u16).unwrap(),
            PseudoPort::Flood => bytes.write_u16::<BigEndian>(OfpPort::OFPPFlood as u16).unwrap(),
            PseudoPort::AllPorts => bytes.write_u16::<BigEndian>(OfpPort::OFPPAll as u16).unwrap(),
            PseudoPort::Controller(_) => {
                bytes.write_u16::<BigEndian>(OfpPort::OFPPController as u16).unwrap()
            }
            PseudoPort::Local => bytes.write_u16::<BigEndian>(OfpPort::OFPPLocal as u16).unwrap(),
        }
    }
}

#[repr(packed)]
struct OfpActionHeader(u16, u16);

#[repr(packed)]
struct OfpActionOutput(u16, u16);
#[repr(packed)]
struct OfpActionVlanVId(u16, u16);
#[repr(packed)]
struct OfpActionVlanPcp(u8, [u8; 3]);
#[repr(packed)]
struct OfpActionStripVlan(u32);
#[repr(packed)]
struct OfpActionDlAddr([u8; 6], [u8; 6]);
#[repr(packed)]
struct OfpActionNwAddr(u32);
#[repr(packed)]
struct OfpActionTpPort(u16, u16);
#[repr(packed)]
struct OfpActionNwTos(u8, [u8; 3]);
#[repr(packed)]
struct OfpActionEnqueue(u16, [u8; 6], u32);

#[repr(u16)]
enum OfpActionType {
    OFPATOutput,
    OFPATSetVlanVId,
    OFPATSetVlanPCP,
    OFPATStripVlan,
    OFPATSetDlSrc,
    OFPATSetDlDst,
    OFPATSetNwSrc,
    OFPATSetNwDst,
    OFPATSetNwTos,
    OFPATSetTpSrc,
    OFPATSetTpDst,
    OFPATEnqueue,
}

create_empty_wrapper!(Action, Action0x01);

impl Action0x01 {
    fn type_code(a: &Action) -> OfpActionType {
        match *a {
            Action::Output(_) => OfpActionType::OFPATOutput,
            Action::SetDlVlan(None) => OfpActionType::OFPATStripVlan,
            Action::SetDlVlan(Some(_)) => OfpActionType::OFPATSetVlanVId,
            Action::SetDlVlanPcp(_) => OfpActionType::OFPATSetVlanPCP,
            Action::SetDlSrc(_) => OfpActionType::OFPATSetDlSrc,
            Action::SetDlDst(_) => OfpActionType::OFPATSetDlDst,
            Action::SetNwSrc(_) => OfpActionType::OFPATSetNwSrc,
            Action::SetNwDst(_) => OfpActionType::OFPATSetNwDst,
            Action::SetNwTos(_) => OfpActionType::OFPATSetNwTos,
            Action::SetTpSrc(_) => OfpActionType::OFPATSetTpSrc,
            Action::SetTpDst(_) => OfpActionType::OFPATSetTpDst,
            Action::Enqueue(_, _) => OfpActionType::OFPATEnqueue,
        }
    }

    fn size_of(a: &Action) -> usize {
        let h = size_of::<OfpActionHeader>();
        let body = match *a {
            Action::Output(_) => size_of::<OfpActionOutput>(),
            Action::SetDlVlan(None) => size_of::<OfpActionStripVlan>(),
            Action::SetDlVlan(Some(_)) => size_of::<OfpActionVlanVId>(),
            Action::SetDlVlanPcp(_) => size_of::<OfpActionVlanPcp>(),
            Action::SetDlSrc(_) |
            Action::SetDlDst(_) => size_of::<OfpActionDlAddr>(),
            Action::SetNwSrc(_) |
            Action::SetNwDst(_) => size_of::<OfpActionNwAddr>(),
            Action::SetNwTos(_) => size_of::<OfpActionNwTos>(),
            Action::SetTpSrc(_) |
            Action::SetTpDst(_) => size_of::<OfpActionTpPort>(),
            Action::Enqueue(_, _) => size_of::<OfpActionEnqueue>(),
        };
        h + body
    }

    fn size_of_sequence(actions: &Vec<Action>) -> usize {
        actions.iter().fold(0, |acc, x| Action0x01::size_of(x) + acc)
    }

    fn _parse(bytes: &mut Cursor<Vec<u8>>) -> Result<Action, OfpSerializationError> {
        let action_code = bytes.read_u16::<BigEndian>().unwrap();
        let _ = bytes.read_u16::<BigEndian>().unwrap();
        let action = match action_code {
            t if t == (OfpActionType::OFPATOutput as u16) => {
                let port_code = bytes.read_u16::<BigEndian>().unwrap();
                let len = bytes.read_u16::<BigEndian>().unwrap();
                Action::Output(PseudoPort0x01::make(port_code, len as u64)?)
            }
            t if t == (OfpActionType::OFPATSetVlanVId as u16) => {
                let vid = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                if vid == 0xffff {
                    Action::SetDlVlan(None)
                } else {
                    Action::SetDlVlan(Some(vid))
                }
            }
            t if t == (OfpActionType::OFPATSetVlanPCP as u16) => {
                let pcp = bytes.read_u8().unwrap();
                bytes.consume(3);
                Action::SetDlVlanPcp(pcp)
            }
            t if t == (OfpActionType::OFPATStripVlan as u16) => {
                bytes.consume(4);
                Action::SetDlVlan(None)
            }
            t if t == (OfpActionType::OFPATSetDlSrc as u16) => {
                let mut dl_addr: [u8; 6] = [0; 6];
                for i in 0..6 {
                    dl_addr[i] = bytes.read_u8().unwrap();
                }
                bytes.consume(6);
                Action::SetDlSrc(mac_of_bytes(dl_addr))
            }
            t if t == (OfpActionType::OFPATSetDlDst as u16) => {
                let mut dl_addr: [u8; 6] = [0; 6];
                for i in 0..6 {
                    dl_addr[i] = bytes.read_u8().unwrap();
                }
                bytes.consume(6);
                Action::SetDlDst(mac_of_bytes(dl_addr))
            }
            t if t == (OfpActionType::OFPATSetNwSrc as u16) => {
                Action::SetNwSrc(bytes.read_u32::<BigEndian>().unwrap())
            }
            t if t == (OfpActionType::OFPATSetNwDst as u16) => {
                Action::SetNwDst(bytes.read_u32::<BigEndian>().unwrap())
            }
            t if t == (OfpActionType::OFPATSetNwTos as u16) => {
                let nw_tos = bytes.read_u8().unwrap();
                bytes.consume(3);
                Action::SetNwTos(nw_tos)
            }
            t if t == (OfpActionType::OFPATSetTpSrc as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                Action::SetTpSrc(pt)
            }
            t if t == (OfpActionType::OFPATSetTpDst as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                Action::SetTpDst(pt)
            }
            t if t == (OfpActionType::OFPATEnqueue as u16) => {
                let pt = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(6);
                let qid = bytes.read_u32::<BigEndian>().unwrap();
                Action::Enqueue(PseudoPort0x01::make(pt, 0)?, qid)
            }
            t => {
                return Result::Err(OfpSerializationError::UnexpectedValueError {
                    value: format!("0x{:x}", t),
                    field: "type".to_string(),
                    message: "action".to_string()
                });
            },
        };
        Ok(action)
    }

    fn parse_sequence(bytes: &mut Cursor<Vec<u8>>) -> Result<Vec<Action>, OfpSerializationError> {
        if bytes.remaining() == 0 {
            Ok(vec![])
        } else {
            let action = Action0x01::_parse(bytes)?;
            let mut v = vec![action];
            v.append(&mut Action0x01::parse_sequence(bytes)?);
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

    fn marshal(act: Action, bytes: &mut Vec<u8>) {
        bytes.write_u16::<BigEndian>(Action0x01::type_code(&act) as u16).unwrap();
        bytes.write_u16::<BigEndian>(Action0x01::size_of(&act) as u16).unwrap();
        match act {
            Action::Output(pp) => {
                PseudoPort0x01::marshal(pp, bytes);
                bytes.write_u16::<BigEndian>(match pp {
                    PseudoPort::Controller(w) => w as u16,
                    _ => 0,
                })
                    .unwrap()
            }
            Action::SetDlVlan(None) => bytes.write_u32::<BigEndian>(0xffff).unwrap(),
            Action::SetDlVlan(Some(vid)) => {
                bytes.write_u16::<BigEndian>(vid).unwrap();
                bytes.write_u16::<BigEndian>(0).unwrap();
            }
            Action::SetDlVlanPcp(n) => {
                bytes.write_u8(n).unwrap();
                for _ in 0..3 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetDlSrc(mac) |
            Action::SetDlDst(mac) => {
                let mac = bytes_of_mac(mac);
                for i in 0..6 {
                    bytes.write_u8(mac[i]).unwrap();
                }
                for _ in 0..6 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetNwSrc(addr) |
            Action::SetNwDst(addr) => bytes.write_u32::<BigEndian>(addr).unwrap(),
            Action::SetNwTos(n) => {
                bytes.write_u8(n).unwrap();
                for _ in 0..3 {
                    bytes.write_u8(0).unwrap();
                }
            }
            Action::SetTpSrc(pt) |
            Action::SetTpDst(pt) => {
                bytes.write_u16::<BigEndian>(pt).unwrap();
                bytes.write_u16::<BigEndian>(0).unwrap();
            }
            Action::Enqueue(pp, qid) => {
                PseudoPort0x01::marshal(pp, bytes);
                for _ in 0..6 {
                    bytes.write_u8(0).unwrap();
                }
                bytes.write_u32::<BigEndian>(qid).unwrap();
            }
        }
    }
}

#[repr(packed)]
struct OfpSwitchFeatures(u64, u32, u8, [u8; 3], u32, u32);

impl MessageType for SwitchFeatures {
    fn size_of(sf: &SwitchFeatures) -> usize {
        let pds: usize = match &sf.ports {
            Some(ports) => {
                ports.iter().map(|pd| PortDesc0x01::size_of(pd)).sum()
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
        bytes.consume(3);
        let supported_capabilities = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            let stp = test_bit(3, d as u64);
            Capabilities {
                flow_stats: test_bit(0, d as u64),
                table_stats: test_bit(1, d as u64),
                port_stats: test_bit(2, d as u64),
                stp,
                port_blocked: stp,
                ip_reasm: test_bit(5, d as u64),
                queue_stats: test_bit(6, d as u64),
                arp_match_ip: test_bit(7, d as u64),
                group_stats: false,
            }
        };
        let supported_actions = {
            let d = bytes.read_u32::<BigEndian>().unwrap();
            SupportedActions {
                output: test_bit(0, d as u64),
                set_vlan_id: test_bit(1, d as u64),
                set_vlan_pcp: test_bit(2, d as u64),
                strip_vlan: test_bit(3, d as u64),
                set_dl_src: test_bit(4, d as u64),
                set_dl_dst: test_bit(5, d as u64),
                set_nw_src: test_bit(6, d as u64),
                set_nw_dst: test_bit(7, d as u64),
                set_nw_tos: test_bit(8, d as u64),
                set_tp_src: test_bit(9, d as u64),
                set_tp_dst: test_bit(10, d as u64),
                enqueue: test_bit(11, d as u64),
                vendor: test_bit(12, d as u64),
            }
        };
        let ports = {
            let mut v = vec![];
            let pos = bytes.position() as usize;
            let rem = bytes.get_ref()[pos..].to_vec();
            let num_ports = rem.len() / size_of::<OfpPhyPort>();
            for _ in 0..num_ports {
                v.push(PortDesc0x01::parse(&mut bytes)?)
            }
            v
        };
        Ok(SwitchFeatures {
            datapath_id: datapath_id,
            num_buffers: num_buffers,
            num_tables: num_tables,
            supported_capabilities: supported_capabilities,
            supported_actions: Some(supported_actions),
            ports: Some(ports),
            auxiliary_id: MAIN_CONNECTION
        })
    }

    fn marshal(_: SwitchFeatures, _: &mut Vec<u8>) {}
}

#[repr(packed)]
struct OfpFlowMod(u64, u16, u16, u16, u16, u32, u16, u16);

create_empty_wrapper!(FlowMod, FlowMod0x01);

impl FlowMod0x01 {
    fn flags_to_int(check_overlap: bool, notify_when_removed: bool) -> u16 {
        (if check_overlap { 1 << 1 } else { 0 }) | (if notify_when_removed { 1 << 0 } else { 0 })
    }

    fn check_overlap_of_flags(flags: u16) -> bool {
        2 & flags != 0
    }

    fn notify_when_removed_of_flags(flags: u16) -> bool {
        1 & flags != 0
    }
}

impl MessageType for FlowMod {
    fn size_of(msg: &FlowMod) -> usize {
        Pattern0x01::size_of(&msg.pattern) + size_of::<OfpFlowMod>() +
        Action0x01::size_of_sequence(&msg.actions)
    }

    fn parse(buf: &[u8]) -> Result<FlowMod, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let pattern = Pattern0x01::parse(&mut bytes);
        let cookie = bytes.read_u64::<BigEndian>().unwrap();
        let command = unsafe { transmute(bytes.read_u16::<BigEndian>().unwrap()) };
        let idle = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        let hard = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        let prio = bytes.read_u16::<BigEndian>().unwrap();
        let buffer_id = bytes.read_i32::<BigEndian>().unwrap();
        let out_port = PseudoPort0x01::of_int(bytes.read_u16::<BigEndian>().unwrap())?;
        let flags = bytes.read_u16::<BigEndian>().unwrap();
        let actions = Action0x01::parse_sequence(&mut bytes)?;
        Ok(FlowMod {
            table: TableId(0),
            command: command,
            pattern: pattern,
            priority: prio,
            actions: actions,
            cookie: cookie,
            idle_timeout: idle,
            hard_timeout: hard,
            notify_when_removed: FlowMod0x01::notify_when_removed_of_flags(flags),
            apply_to_packet: {
                match buffer_id {
                    -1 => None,
                    n => Some(n as u32),
                }
            },
            out_port: out_port,
            check_overlap: FlowMod0x01::check_overlap_of_flags(flags),
        })
    }

    fn marshal(fm: FlowMod, bytes: &mut Vec<u8>) {
        Pattern0x01::marshal(fm.pattern, bytes);
        bytes.write_u64::<BigEndian>(fm.cookie).unwrap();
        bytes.write_u16::<BigEndian>(fm.command as u16).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(fm.idle_timeout)).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(fm.hard_timeout)).unwrap();
        bytes.write_u16::<BigEndian>(fm.priority).unwrap();
        bytes.write_i32::<BigEndian>(match fm.apply_to_packet {
                None => -1,
                Some(buf_id) => buf_id as i32,
            })
            .unwrap();
        match fm.out_port {
            None => bytes.write_u16::<BigEndian>(OfpPort::OFPPNone as u16).unwrap(),
            Some(x) => PseudoPort0x01::marshal(x, bytes),
        }
        bytes.write_u16::<BigEndian>(FlowMod0x01::flags_to_int(fm.check_overlap,
                                                          fm.notify_when_removed))
            .unwrap();
        for act in Action0x01::move_controller_last(fm.actions) {
            match act {
                Action::Output(PseudoPort::Table) => {
                    panic!("OFPPTable not allowed in installed flow.")
                }
                _ => (),
            }
            Action0x01::marshal(act, bytes)
        }
    }
}

#[repr(u32)]
pub enum OfpQueue {
    OFPQAll = 0xffffffff,
}

create_empty_wrapper!(StatsReqType, StatsReqType0x01);

impl StatsReqType0x01 {
    pub fn from_u16(value: u16) -> StatsReqType {
        match value {
            0 => StatsReqType::Desc,
            1 => StatsReqType::Flow,
            2 => StatsReqType::Aggregate,
            3 => StatsReqType::Table,
            4 => StatsReqType::Port,
            5 => StatsReqType::Queue,
            0xFFFF => StatsReqType::Vendor,
            _ => StatsReqType::Vendor // What to default here?
        }
    }
}

#[repr(packed)]
struct OfpStatsReq(u16, u16);
#[repr(packed)]
struct OfpStatsReqFlowBody(u8, u8, u16);
#[repr(packed)]
struct OfpStatsReqPortBody(u16, [u8; 6]);
#[repr(packed)]
struct OfpStatsReqQueueBody(u16, [u8; 2], u32);

impl StatsReq {
}

impl MessageType for StatsReq {
    fn size_of(msg: &StatsReq) -> usize {
        size_of::<OfpStatsReq>() +
            match &msg.body {
                StatsReqBody::DescBody => 0,
                StatsReqBody::FlowStatsBody{ pattern, .. } => Pattern0x01::size_of(&pattern) + size_of::<OfpStatsReqFlowBody>(),
                StatsReqBody::TableBody => 0,
                StatsReqBody::PortBody{ .. } => size_of::<OfpStatsReqPortBody>(),
                StatsReqBody::QueueBody{ .. } => size_of::<OfpStatsReqQueueBody>(),
                StatsReqBody::VendorBody => 0
            }
    }

    fn parse(buf: &[u8]) -> Result<StatsReq, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let req_type = StatsReqType0x01::from_u16(bytes.read_u16::<BigEndian>().unwrap());
        let flags = bytes.read_u16::<BigEndian>().unwrap();
        let body = match req_type {
            StatsReqType::Desc => StatsReqBody::DescBody,
            StatsReqType::Flow | StatsReqType::Aggregate => {
                let pattern = Pattern0x01::parse(&mut bytes);
                let table_id = bytes.read_u8().unwrap();
                bytes.consume(1);
                let out_port = bytes.read_u16::<BigEndian>().unwrap();

                StatsReqBody::FlowStatsBody {
                    pattern, table_id, out_port
                }
            },
            StatsReqType::Table => StatsReqBody::TableBody,
            StatsReqType::Port => {
                let port_no = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(6);
                StatsReqBody::PortBody {
                    port_no
                }
            },
            StatsReqType::Queue => {
                let port_no = bytes.read_u16::<BigEndian>().unwrap();
                bytes.consume(2);
                let queue_id = bytes.read_u32::<BigEndian>().unwrap();
                StatsReqBody::QueueBody {
                    port_no,
                    queue_id
                }
            },
            StatsReqType::Vendor => {
                StatsReqBody::VendorBody {}
            }
        };

        Ok(StatsReq {
            req_type,
            flags,
            body
        })
    }

    fn marshal(sr: StatsReq, bytes: &mut Vec<u8>) {
        bytes.write_u16::<BigEndian>(sr.req_type as u16).unwrap();
        bytes.write_u16::<BigEndian>(sr.flags).unwrap();
        match sr.body {
            StatsReqBody::DescBody => {},
            StatsReqBody::FlowStatsBody{pattern, table_id, out_port} => {
                Pattern0x01::marshal(pattern, bytes);
                bytes.write_u8(table_id).unwrap();
                write_padding_bytes(bytes, 1);
                bytes.write_u16::<BigEndian>(out_port).unwrap();
            },
            StatsReqBody::TableBody => {},
            StatsReqBody::PortBody{ port_no } => {
                bytes.write_u16::<BigEndian>(port_no).unwrap();
                write_padding_bytes(bytes, 6);
            },
            StatsReqBody::QueueBody{ port_no, queue_id } => {
                bytes.write_u16::<BigEndian>(port_no).unwrap();
                write_padding_bytes(bytes, 2);
                bytes.write_u32::<BigEndian>(queue_id).unwrap();
            },
            StatsReqBody::VendorBody => {}
        }
    }
}

create_empty_wrapper!(TransmissionCounter, TransmissionCounter0x01);

impl TransmissionCounter0x01 {
    fn from_bytes(bytes: &mut Cursor<Vec<u8>>) -> io::Result<TransmissionCounter> {
        let rx = bytes.read_u64::<BigEndian>()?;
        let tx = bytes.read_u64::<BigEndian>()?;

        Ok(TransmissionCounter {rx, tx})
    }
}

#[repr(packed)]
struct OfpStatsResp(u16, u16);
#[repr(packed)]
struct OfpStatsRespDescBody([char; DESC_STR_LENGTH], [char; DESC_STR_LENGTH],
                            [char; DESC_STR_LENGTH], [char; SERIAL_NUM_LENGTH],
                            [char; DESC_STR_LENGTH]);
#[repr(packed)]
struct OfpStatsRespFlowStats(u16, u8, u8, u32, u32, u16, u16, u16, [u8; 6],
                             u64, u64, u64);
#[repr(packed)]
struct OfpStatsRespAggregateBody(u64, u64, u32, [u8; 4]);
#[repr(packed)]
struct OfpStatsRespTableStats(u8, [u8; 3], [char; OFP_MAX_TABLE_NAME_LENGTH],
                             u32, u32, u32, u64, u64);
#[repr(packed)]
struct OfpStatsRespQueueStats(u16, [u8; 2], u32, u64, u64, u64);
#[repr(packed)]
struct OfpStatsRespPortStats(u16, [u8; 6], [u64; 2],
                             [u64; 2], [u64; 2], [u64; 2],
                             u64, u64, u64, u64);

create_empty_wrapper!(FlowStats, FlowStats0x01);

impl FlowStats0x01 {
    fn size_of(stats : &FlowStats) -> usize {
        Pattern0x01::size_of(&stats.pattern) +
            size_of::<OfpStatsRespFlowStats>() +
            Action0x01::size_of_sequence(&stats.actions)
    }
}

impl StatsResp {
}

impl MessageType for StatsResp {
    fn size_of(msg: &StatsResp) -> usize {
        size_of::<OfpStatsResp>() +
            match msg.body {
                StatsRespBody::DescBody{ .. } => size_of::<OfpStatsRespDescBody>(),
                StatsRespBody::FlowStatsBody{ ref flow_stats } =>
                    flow_stats.iter().map(|stats| FlowStats0x01::size_of(stats)).sum(),
                StatsRespBody::AggregateStatsBody{ .. } => size_of::<OfpStatsRespAggregateBody>(),
                StatsRespBody::TableBody{ ref table_stats } =>
                    table_stats.len() * size_of::<OfpStatsRespTableStats>(),
                StatsRespBody::PortBody{ ref port_stats } =>
                    port_stats.len() * size_of::<OfpStatsRespPortStats>(),
                StatsRespBody::QueueBody{ ref queue_stats } =>
                    queue_stats.len() * size_of::<OfpStatsRespQueueStats>(),
                StatsRespBody::VendorBody => 0
            }
    }

    fn parse(buf: &[u8]) -> Result<StatsResp, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let req_type = StatsReqType0x01::from_u16(bytes.read_u16::<BigEndian>().unwrap());
        let flags = bytes.read_u16::<BigEndian>().unwrap();
        let body = match req_type {
            StatsReqType::Desc => {
                let manufacturer_desc = read_fixed_size_string(&mut bytes, DESC_STR_LENGTH);
                let hardware_desc = read_fixed_size_string(&mut bytes, DESC_STR_LENGTH);
                let software_desc = read_fixed_size_string(&mut bytes, DESC_STR_LENGTH);
                let serial_number = read_fixed_size_string(&mut bytes, SERIAL_NUM_LENGTH);
                let datapath_desc = read_fixed_size_string(&mut bytes, DESC_STR_LENGTH);

                StatsRespBody::DescBody {
                    manufacturer_desc,
                    hardware_desc,
                    software_desc,
                    serial_number,
                    datapath_desc
                }
            },
            StatsReqType::Flow => {
                let mut flow_stats = Vec::<FlowStats>::new();

                while bytes.remaining() > 0 {
                    let entry_length = bytes.read_u16::<BigEndian>().unwrap() as usize;
                    if bytes.remaining() + 2 < entry_length {
                        // TODO error
                        warn!("Error parsing flow stats response: length too short: {} {}",
                              bytes.remaining() + 2, entry_length);
                        break;
                    }

                    // TODO handle entry_length == 0 broken packets

                    let mut flow_data = vec![0; entry_length - 2];
                    bytes.read_exact(&mut flow_data).unwrap();
                    let mut flow = Cursor::new(flow_data);

                    let table_id = flow.read_u8().unwrap();
                    flow.consume(1);
                    let pattern = Pattern0x01::parse(&mut flow);
                    let duration_sec = flow.read_u32::<BigEndian>().unwrap();
                    let duration_nsec = flow.read_u32::<BigEndian>().unwrap();
                    let priority = flow.read_u16::<BigEndian>().unwrap();
                    let idle_timeout = flow.read_u16::<BigEndian>().unwrap();
                    let hard_timeout = flow.read_u16::<BigEndian>().unwrap();
                    flow.consume(6);
                    let cookie = flow.read_u64::<BigEndian>().unwrap();
                    let packet_count = flow.read_u64::<BigEndian>().unwrap();
                    let byte_count = flow.read_u64::<BigEndian>().unwrap();
                    let actions = Action0x01::parse_sequence(&mut flow)?;

                    flow_stats.push(FlowStats {
                        table_id,
                        pattern,
                        duration_sec,
                        duration_nsec,
                        priority,
                        idle_timeout,
                        hard_timeout,
                        cookie,
                        packet_count,
                        byte_count,
                        actions
                    });
                }

                StatsRespBody::FlowStatsBody {
                    flow_stats
                }
            },
            StatsReqType::Aggregate => {
                let packet_count = bytes.read_u64::<BigEndian>().unwrap();
                let byte_count = bytes.read_u64::<BigEndian>().unwrap();
                let flow_count = bytes.read_u32::<BigEndian>().unwrap();
                bytes.consume(4);

                StatsRespBody::AggregateStatsBody {
                    packet_count, byte_count, flow_count
                }
            },
            StatsReqType::Table => {
                let mut table_stats = Vec::<TableStats>::new();
                while bytes.remaining() > size_of::<OfpStatsRespTableStats>() {
                    let table_id = bytes.read_u8().unwrap();
                    bytes.consume(3);
                    let mut name: [u8; OFP_MAX_TABLE_NAME_LENGTH] = [0; OFP_MAX_TABLE_NAME_LENGTH];
                    bytes.read(&mut name).unwrap();
                    let wildcards_int = bytes.read_u32::<BigEndian>().unwrap();
                    let wildcards = Wildcards0x01::parse(wildcards_int);
                    let max_entries = bytes.read_u32::<BigEndian>().unwrap();
                    let active_count = bytes.read_u32::<BigEndian>().unwrap();
                    let lookup_count = bytes.read_u64::<BigEndian>().unwrap();
                    let matched_count = bytes.read_u64::<BigEndian>().unwrap();

                    table_stats.push(TableStats {
                        table_id,
                        name: String::from_utf8(name.to_vec()).unwrap(),
                        wildcards,
                        max_entries,
                        active_count,
                        lookup_count,
                        matched_count
                    });
                }

                StatsRespBody::TableBody {
                    table_stats
                }
            },
            StatsReqType::Port => {
                let mut port_stats = Vec::<PortStats>::new();

                while bytes.remaining() >= size_of::<OfpStatsRespPortStats>() {
                    let port_no = bytes.read_u16::<BigEndian>().unwrap();
                    bytes.consume(6);
                    let packets = TransmissionCounter0x01::from_bytes(&mut bytes).unwrap();
                    let bytes_counter = TransmissionCounter0x01::from_bytes(&mut bytes).unwrap();
                    let dropped = TransmissionCounter0x01::from_bytes(&mut bytes).unwrap();
                    let errors = TransmissionCounter0x01::from_bytes(&mut bytes).unwrap();
                    let rx_frame_errors = bytes.read_u64::<BigEndian>().unwrap();
                    let rx_over_errors = bytes.read_u64::<BigEndian>().unwrap();
                    let rx_crc_errors = bytes.read_u64::<BigEndian>().unwrap();
                    let collisions = bytes.read_u64::<BigEndian>().unwrap();

                    port_stats.push(PortStats {
                        port_no,
                        packets,
                        bytes: bytes_counter,
                        dropped,
                        errors,
                        rx_frame_errors,
                        rx_over_errors,
                        rx_crc_errors,
                        collisions
                    });
                }

                StatsRespBody::PortBody {
                    port_stats
                }
            },
            StatsReqType::Queue => {
                let mut queue_stats = Vec::<QueueStats>::new();

                while bytes.remaining() > size_of::<OfpStatsRespQueueStats>() {
                    let port_no = bytes.read_u16::<BigEndian>().unwrap();
                    bytes.consume(2);
                    let queue_id = bytes.read_u32::<BigEndian>().unwrap();
                    let tx_bytes = bytes.read_u64::<BigEndian>().unwrap();
                    let tx_packets = bytes.read_u64::<BigEndian>().unwrap();
                    let tx_errors = bytes.read_u64::<BigEndian>().unwrap();

                    queue_stats.push(QueueStats {
                        port_no,
                        queue_id,
                        tx_bytes,
                        tx_packets,
                        tx_errors
                    });
                }

                StatsRespBody::QueueBody {
                    queue_stats
                }
            },
            StatsReqType::Vendor => {
                StatsRespBody::VendorBody {}
            }
        };

        Ok(StatsResp {
            req_type,
            flags,
            body
        })
    }

    fn marshal(sr: StatsResp, bytes: &mut Vec<u8>) {
        bytes.write_u16::<BigEndian>(sr.req_type as u16).unwrap();
        bytes.write_u16::<BigEndian>(sr.flags).unwrap();
        /*
        match sr.body {
            StatsReqBody::DescBody => {},
            StatsReqBody::FlowStatsBody{pattern, table_id, out_port} => {
                Pattern::marshal(pattern, bytes);
                bytes.write_u8(table_id).unwrap();
                write_padding_bytes(bytes, 1);
                bytes.write_u16::<BigEndian>(out_port).unwrap();
            },
            StatsReqBody::TableBody => {},
            StatsReqBody::PortBody{ port_no } => {
                bytes.write_u16::<BigEndian>(port_no).unwrap();
                write_padding_bytes(bytes, 6);
            },
            StatsReqBody::QueueBody{ port_no, queue_id } => {
                bytes.write_u16::<BigEndian>(port_no).unwrap();
                write_padding_bytes(bytes, 2);
                bytes.write_u32::<BigEndian>(queue_id).unwrap();
            },
            StatsReqBody::VendorBody => {}
        }
        */
    }
}


create_empty_wrapper!(Payload, Payload0x01);

impl Payload0x01 {
    fn marshal(payload: Payload, bytes: &mut Vec<u8>) {
        match payload {
            Payload::Buffered(_, buf) |
            Payload::NotBuffered(buf) => bytes.write_all(&buf).unwrap(),
        }
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
        let port = bytes.read_u16::<BigEndian>().unwrap();
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

    fn marshal(pi: PacketIn, bytes: &mut Vec<u8>) {
        let buf_id = match pi.input_payload {
            Payload::NotBuffered(_) => -1,
            Payload::Buffered(n, _) => n as i32,
        };
        bytes.write_i32::<BigEndian>(buf_id).unwrap();
        bytes.write_u16::<BigEndian>(pi.total_len).unwrap();
        bytes.write_u16::<BigEndian>(pi.port).unwrap();
        bytes.write_u8(pi.reason as u8).unwrap();
        bytes.write_u8(0).unwrap(); // Padding
        Payload0x01::marshal(pi.input_payload, bytes)
    }
}

#[repr(packed)]
struct OfpPacketOut(u32, u16, u16);

impl MessageType for PacketOut {
    fn size_of(po: &PacketOut) -> usize {
        size_of::<OfpPacketOut>() + Action0x01::size_of_sequence(&po.apply_actions) +
        Payload::size_of(&po.output_payload)
    }

    fn parse(buf: &[u8]) -> Result<PacketOut, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let buf_id = match bytes.read_i32::<BigEndian>().unwrap() {
            -1 => None,
            n => Some(n),
        };
        let in_port = bytes.read_u16::<BigEndian>().unwrap();
        let actions_len = bytes.read_u16::<BigEndian>().unwrap();
        let mut actions_buf = vec![0; actions_len as usize];
        bytes.read_exact(&mut actions_buf).unwrap();
        let mut actions_bytes = Cursor::new(actions_buf);
        let actions = Action0x01::parse_sequence(&mut actions_bytes)?;
        Ok(PacketOut {
            output_payload: match buf_id {
                None => Payload::NotBuffered(bytes.fill_buf().unwrap().to_vec()),
                Some(n) => Payload::Buffered(n as u32, bytes.fill_buf().unwrap().to_vec()),
            },
            port_id: {
                if in_port == OfpPort::OFPPNone as u16 {
                    None
                } else {
                    Some(in_port)
                }
            },
            apply_actions: actions,
        })
    }

    fn marshal(po: PacketOut, bytes: &mut Vec<u8>) {
        bytes.write_i32::<BigEndian>(match po.output_payload {
                Payload::Buffered(n, _) => n as i32,
                Payload::NotBuffered(_) => -1,
            })
            .unwrap();
        match po.port_id {
            Some(id) => PseudoPort0x01::marshal(PseudoPort::PhysicalPort(id), bytes),
            None => bytes.write_u16::<BigEndian>(OfpPort::OFPPNone as u16).unwrap(),
        }
        bytes.write_u16::<BigEndian>(Action0x01::size_of_sequence(&po.apply_actions) as u16).unwrap();
        for act in Action0x01::move_controller_last(po.apply_actions) {
            Action0x01::marshal(act, bytes);
        }
        Payload0x01::marshal(po.output_payload, bytes)
    }
}

#[repr(packed)]
struct OfpFlowRemoved(u64, u16, u8, u8, u32, u32, u16, u16, u64, u64);

impl MessageType for FlowRemoved {
    fn size_of(f: &FlowRemoved) -> usize {
        Pattern0x01::size_of(&f.pattern) + size_of::<OfpFlowRemoved>()
    }

    fn parse(buf: &[u8]) -> Result<FlowRemoved, OfpSerializationError> {
        let mut bytes = Cursor::new(buf.to_vec());
        let pattern = Pattern0x01::parse(&mut bytes);
        let cookie = bytes.read_i64::<BigEndian>().unwrap();
        let priority = bytes.read_u16::<BigEndian>().unwrap();
        let reason = unsafe { transmute(bytes.read_u8().unwrap()) };
        bytes.consume(1);
        let duration_sec = bytes.read_u32::<BigEndian>().unwrap();
        let duration_nsec = bytes.read_u32::<BigEndian>().unwrap();
        let idle = Timeout::of_int(bytes.read_u16::<BigEndian>().unwrap());
        bytes.consume(2);
        let packet_count = bytes.read_u64::<BigEndian>().unwrap();
        let byte_count = bytes.read_u64::<BigEndian>().unwrap();
        Ok(FlowRemoved {
            pattern: pattern,
            cookie: cookie,
            priority: priority,
            reason: reason,
            duration_sec: duration_sec,
            duration_nsec: duration_nsec,
            idle_timeout: idle,
            packet_count: packet_count,
            byte_count: byte_count,
        })
    }

    fn marshal(f: FlowRemoved, bytes: &mut Vec<u8>) {
        Pattern0x01::marshal(f.pattern, bytes);
        bytes.write_i64::<BigEndian>(f.cookie).unwrap();
        bytes.write_u16::<BigEndian>(f.priority).unwrap();
        bytes.write_u8(f.reason as u8).unwrap();
        bytes.write_u8(0).unwrap();
        bytes.write_u32::<BigEndian>(f.duration_sec).unwrap();
        bytes.write_u32::<BigEndian>(f.duration_nsec).unwrap();
        bytes.write_u16::<BigEndian>(Timeout::to_int(f.idle_timeout)).unwrap();
        write_padding_bytes(bytes, 2);
        bytes.write_u64::<BigEndian>(f.packet_count).unwrap();
        bytes.write_u64::<BigEndian>(f.byte_count).unwrap();
    }
}

create_empty_wrapper!(PortFeatures, PortFeatures0x01);

impl PortFeatures0x01 {
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

create_empty_wrapper!(PortDesc, PortDesc0x01);

impl PortDesc0x01 {
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
        let curr = PortFeatures0x01::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let advertised = PortFeatures0x01::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let supported = PortFeatures0x01::of_int(bytes.read_u32::<BigEndian>().unwrap());
        let peer = PortFeatures0x01::of_int(bytes.read_u32::<BigEndian>().unwrap());
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
        let desc = PortDesc0x01::parse(&mut bytes)?;
        Ok(PortStatus {
            reason: reason,
            desc: desc,
        })
    }

    fn marshal(_: PortStatus, _: &mut Vec<u8>) {}
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

    fn marshal(_: Error, _: &mut Vec<u8>) {}
}

/// Encapsulates handling of messages implementing `MessageType` trait.
pub mod message {
    use super::*;
    use std::io::Write;
    use ofp_header::{OfpHeader, OPENFLOW_0_01_VERSION};
    use ofp_message::{OfpMessage, OfpSerializationError};
    use packet::Packet;
    use openflow::MsgCode;

    pub struct Message0x01 {
        inner: Message
    }

    impl From<Message> for Message0x01 {
        fn from(m: Message) -> Self {
            Message0x01 { inner: m }
        }
    }

    impl Message0x01 {

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
                Message::StatsRequest(_) => MsgCode::StatsReq,
                Message::StatsReply(_) => MsgCode::StatsResp,
            }
        }

        fn msg_code_to_u8(msgcode: &MsgCode) -> Result<u8, OfpSerializationError> {
            match msgcode {
                MsgCode::Hello => Ok(0),
                MsgCode::Error => Ok(1),
                MsgCode::EchoReq => Ok(2),
                MsgCode::EchoResp => Ok(3),
                MsgCode::Vendor => Ok(4),
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
                MsgCode::PortMod => Ok(15),
                MsgCode::StatsReq => Ok(16),
                MsgCode::StatsResp => Ok(17),
                MsgCode::BarrierReq => Ok(18),
                MsgCode::BarrierResp => Ok(19),
                MsgCode::QueueGetConfigReq => Ok(20),
                MsgCode::QueueGetConfigResp => Ok(21),
                c => Err(OfpSerializationError::UnsupportedMessageCode {
                    version: OPENFLOW_0_01_VERSION,
                    code: *c
                })
            }
        }

        fn msg_code_of_message_u8(msg: &Message) -> Result<u8, OfpSerializationError> {
            Self::msg_code_to_u8(&Self::msg_code_of_message(msg))
        }

        /// Marshal the OpenFlow message `msg`.
        fn marshal_body(msg: Message, bytes: &mut Vec<u8>) {
            match msg {
                Message::Hello => (),
                Message::Error(buf) => Error::marshal(buf, bytes),
                Message::EchoReply(buf) => bytes.write_all(&buf).unwrap(),
                Message::EchoRequest(buf) => bytes.write_all(&buf).unwrap(),
                Message::FeaturesReq => (),
                Message::FlowMod(flow_mod) => FlowMod::marshal(flow_mod, bytes),
                Message::PacketIn(packet_in) => PacketIn::marshal(packet_in, bytes),
                Message::FlowRemoved(flow) => FlowRemoved::marshal(flow, bytes),
                Message::PortStatus(sts) => PortStatus::marshal(sts, bytes),
                Message::PacketOut(po) => PacketOut::marshal(po, bytes),
                Message::BarrierRequest | Message::BarrierReply => (),
                Message::StatsRequest(stats_req) => StatsReq::marshal(stats_req, bytes),
                _ => (),
            }
        }
    }

    impl OfpMessage for Message0x01 {
        fn size_of(msg: &Message0x01) -> usize {
            match msg.inner {
                Message::Hello => OfpHeader::size(),
                Message::Error(ref err) => Error::size_of(err),
                Message::EchoRequest(ref buf) => OfpHeader::size() + buf.len(),
                Message::EchoReply(ref buf) => OfpHeader::size() + buf.len(),
                Message::FeaturesReq => OfpHeader::size(),
                Message::FlowMod(ref flow_mod) => OfpHeader::size() + FlowMod::size_of(flow_mod),
                Message::PacketIn(ref packet_in) => {
                    OfpHeader::size() + PacketIn::size_of(packet_in)
                }
                Message::FlowRemoved(ref flow) => OfpHeader::size() + FlowRemoved::size_of(flow),
                Message::PortStatus(ref ps) => OfpHeader::size() + PortStatus::size_of(ps),
                Message::PacketOut(ref po) => OfpHeader::size() + PacketOut::size_of(po),
                Message::BarrierRequest | Message::BarrierReply => OfpHeader::size(),
                Message::StatsRequest(ref sr) => OfpHeader::size() + StatsReq::size_of(sr),
                Message::StatsReply(ref sr) => OfpHeader::size() + StatsResp::size_of(sr),
                _ => 0,
            }
        }

        fn header_of(xid: u32, msg: &Message0x01) -> Result<OfpHeader, OfpSerializationError> {
            let sizeof_buf = Self::size_of(&msg);
            Ok(OfpHeader::new(OPENFLOW_0_01_VERSION,
                           Self::msg_code_of_message_u8(&msg.inner)?,
                           sizeof_buf as u16,
                           xid))
        }

        fn marshal(xid: u32, msg: Message0x01) -> Result<Vec<u8>, OfpSerializationError> {
            let hdr = Self::header_of(xid, &msg);
            let mut bytes = vec![];
            OfpHeader::marshal(&mut bytes, hdr?);
            Message0x01::marshal_body(msg.inner, &mut bytes);
            Ok(bytes)
        }

        fn parse(header: &OfpHeader, buf: &[u8]) -> Result<(u32, Message0x01), OfpSerializationError> {
            let typ = header.type_code();
            let msg = Message0x01 { inner: match typ {
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
                MsgCode::FlowMod => {
                    debug!("Message received: FlowMod");
                    Message::FlowMod(FlowMod::parse(buf)?)
                }
                MsgCode::PacketIn => {
                    debug!("Message received: PacketIn");
                    Message::PacketIn(PacketIn::parse(buf)?)
                }
                MsgCode::FlowRemoved => {
                    debug!("Message received: FlowRemoved");
                    Message::FlowRemoved(FlowRemoved::parse(buf)?)
                }
                MsgCode::PortStatus => {
                    debug!("Message received: PortStatus");
                    Message::PortStatus(PortStatus::parse(buf)?)
                }
                MsgCode::PacketOut => {
                    debug!("Message received: PacketOut");
                    Message::PacketOut(PacketOut::parse(buf)?)
                }
                MsgCode::BarrierReq => Message::BarrierRequest,
                MsgCode::BarrierResp => Message::BarrierReply,
                MsgCode::StatsResp => Message::StatsReply(StatsResp::parse(buf)?),
                code => return Result::Err(OfpSerializationError::UnexpectedValueError {
                    value: format!("0x{:x}", code as u8),
                    field: "message type".to_string(),
                    message: "message header".to_string()
                }),
            }};
            Ok((header.xid(), msg))
        }
    }

    /// Return a `FlowMod` adding a flow parameterized by the given `priority`, `pattern`,
    /// and `actions`.
    pub fn add_flow(prio: u16, pattern: Pattern, actions: Vec<Action>) -> FlowMod {
        FlowMod {
            table: TableId(0),
            command: FlowModCmd::AddFlow,
            pattern: pattern,
            priority: prio,
            actions: actions,
            cookie: 0,
            idle_timeout: Timeout::Permanent,
            hard_timeout: Timeout::Permanent,
            notify_when_removed: false,
            out_port: None,
            apply_to_packet: None,
            check_overlap: false,
        }
    }

    /// Parse a payload buffer into a network level packet.
    pub fn parse_payload(p: &Payload) -> Packet {
        match *p {
            Payload::Buffered(_, ref b) |
            Payload::NotBuffered(ref b) => Packet::parse(&b),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::File;

        const TEST_XID: u32 = 0x12345678;
        const TEST_DPID: u64 = 0x001122334455667788;

        fn error_vector() -> Vec<u8> {
            vec![0xAB; 10]
        }

        fn echo_vector() -> Vec<u8> {
            vec![0xAB; 5]
        }

        fn port_desc() -> PortDesc {
            PortDesc {
                port_no: 1,
                hw_addr: 0xAABBCCDDEEFF,
                name: "port_1".to_string(),
                config: PortConfig {
                    down: false,
                    no_stp: false,
                    no_recv: false,
                    no_recv_stp: true,
                    no_flood: false,
                    no_fwd: false,
                    no_packet_in: false,
                },
                state: PortState {
                    down: false,
                    stp_state: StpState::Listen,
                },
                curr: PortFeatures {
                    f_10mbhd: true,
                    f_10mbfd: true,
                    f_100mbhd: true,
                    f_100mbfd: true,
                    f_1gbhd: true,
                    f_1gbfd: true,
                    f_10gbfd: false,
                    copper: true,
                    fiber: false,
                    autoneg: true,
                    pause: true,
                    pause_asym: true,
                },
                advertised: PortFeatures {
                    f_10mbhd: true,
                    f_10mbfd: true,
                    f_100mbhd: true,
                    f_100mbfd: true,
                    f_1gbhd: true,
                    f_1gbfd: true,
                    f_10gbfd: false,
                    copper: true,
                    fiber: false,
                    autoneg: true,
                    pause: true,
                    pause_asym: true,
                },
                supported: PortFeatures {
                    f_10mbhd: true,
                    f_10mbfd: true,
                    f_100mbhd: true,
                    f_100mbfd: true,
                    f_1gbhd: true,
                    f_1gbfd: true,
                    f_10gbfd: false,
                    copper: true,
                    fiber: false,
                    autoneg: true,
                    pause: true,
                    pause_asym: true,
                },
                peer: PortFeatures {
                    f_10mbhd: true,
                    f_10mbfd: true,
                    f_100mbhd: true,
                    f_100mbfd: true,
                    f_1gbhd: false,
                    f_1gbfd: false,
                    f_10gbfd: false,
                    copper: true,
                    fiber: false,
                    autoneg: true,
                    pause: true,
                    pause_asym: true,
                }
            }
        }

        fn switch_ports() -> Vec<PortDesc> {
            let mut vec = vec!();
            vec.push(port_desc());

            vec
        }

        fn switch_features() -> SwitchFeatures {
            SwitchFeatures {
                datapath_id: TEST_DPID,
                num_buffers: 200,
                num_tables: 254,
                auxiliary_id: 0,
                supported_capabilities: Capabilities {
                    flow_stats: true,
                    table_stats: true,
                    port_stats: true,
                    stp: false,
                    ip_reasm: false,
                    queue_stats: false,
                    arp_match_ip: false,
                    group_stats: false,
                    port_blocked: false
                },
                supported_actions: Some(SupportedActions {
                    output: true,
                    set_vlan_id: false,
                    set_vlan_pcp: false,
                    strip_vlan: false,
                    set_dl_src: true,
                    set_dl_dst: true,
                    set_nw_src: true,
                    set_nw_dst: true,
                    set_nw_tos: false,
                    set_tp_src: true,
                    set_tp_dst: true,
                    enqueue: false,
                    vendor: false,
                }),
                ports: Some(switch_ports()),
            }
        }

        fn flow_mod_pattern() -> Pattern {
            Pattern {
                dl_src: None,
                dl_dst: None,
                dl_typ: Some(0x0800),
                dl_vlan: None,
                dl_vlan_pcp: None,
                nw_src: None,
                nw_dst: Some(Mask {
                    value: 0x10000001,
                    mask: Some(8) // This is the opposite of a regular network mask
                }),
                nw_proto: Some(6),
                nw_tos: None,
                tp_src: Some(3000),
                tp_dst: Some(4000),
                in_port: Some(1),
            }
        }

        fn flow_mod_actions() -> Vec<Action> {
            let mut actions = Vec::new();

            actions.push(Action::SetDlDst(0x1234567890AB));
            actions.push(Action::Output(PseudoPort::PhysicalPort(1)));

            actions
        }

        fn flow_mod() -> FlowMod {
            FlowMod {
                table: TableId(0),
                command: FlowModCmd::AddFlow,
                pattern: flow_mod_pattern(),
                priority: 16,
                actions: flow_mod_actions(),
                cookie: 0x1234567887654321,
                idle_timeout: Timeout::ExpiresAfter(180),
                hard_timeout: Timeout::Permanent,
                notify_when_removed: true,
                apply_to_packet: None,
                out_port: None,
                check_overlap: true,
            }
        }

        fn flow_removed() -> FlowRemoved {
            FlowRemoved {
                pattern: flow_mod_pattern(),
                cookie: 0x1234567887654321,
                priority: 22,
                reason: FlowRemovedReason::IdleTimeout,
                duration_sec: 123,
                duration_nsec: 123456,
                idle_timeout: Timeout::ExpiresAfter(60),
                packet_count: 100,
                byte_count: 120500
            }
        }

        fn packet_data() -> Vec<u8> {
            let data: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            data.to_vec()
        }

        fn packet_in() -> PacketIn {
            PacketIn {
                input_payload: Payload::NotBuffered(packet_data()),
                total_len: 10,
                port: 1,
                reason: PacketInReason::ExplicitSend
            }
        }

        fn packet_out() -> PacketOut {
            PacketOut {
                output_payload: Payload::NotBuffered(packet_data()),
                port_id: Some(1),
                apply_actions: flow_mod_actions()
            }
        }

        fn port_status() -> PortStatus {
            PortStatus {
                reason: PortReason::PortAdd,
                desc: port_desc()
            }
        }

        fn port_stats_request() -> StatsReq {
            StatsReq {
                req_type: StatsReqType::Port,
                flags: 0,
                body: StatsReqBody::PortBody {
                    port_no: OfpPort::OFPPAll as u16
                }
            }
        }

        fn port_stats_reply() -> StatsResp {
            StatsResp {
                req_type: StatsReqType::Port,
                flags: 0,
                body: StatsRespBody::PortBody {
                    port_stats: port_stats_vec()
                }
            }
        }

        fn port_stats_vec() -> Vec<PortStats> {
            let mut vec = vec!();
            vec.push(PortStats {
                port_no: 1,
                packets: TransmissionCounter{ rx: 1000, tx: 2000 },
                bytes: TransmissionCounter{ rx: 536870912, tx: 1073741824 },
                dropped: TransmissionCounter{ rx: 5, tx: 0},
                errors: TransmissionCounter{ rx: 0, tx: 0},
                rx_frame_errors: 1,
                rx_over_errors: 2,
                rx_crc_errors: 3,
                collisions: 4
            });
            vec.push(PortStats {
                port_no: 2,
                packets: TransmissionCounter{ rx: 0, tx: 0 },
                bytes: TransmissionCounter{ rx: 0, tx: 0 },
                dropped: TransmissionCounter{ rx: 0, tx: 0},
                errors: TransmissionCounter{ rx: 0, tx: 0},
                rx_frame_errors: 0,
                rx_over_errors: 0,
                rx_crc_errors: 0,
                collisions: 0
            });
            vec
        }

        fn desc_stats_request() -> StatsReq {
            StatsReq {
                req_type: StatsReqType::Desc,
                flags: 0,
                body: StatsReqBody::DescBody
            }
        }

        fn desc_stats_reply() -> StatsResp {
            StatsResp {
                req_type: StatsReqType::Desc,
                flags: 0,
                body: StatsRespBody::DescBody {
                    manufacturer_desc: "manufacturer".to_string(),
                    hardware_desc: "hardware".to_string(),
                    software_desc: "software".to_string(),
                    serial_number: "12345".to_string(),
                    datapath_desc: "dp001".to_string()
                }
            }
        }

        fn flow_stats_request() -> StatsReq {
            StatsReq {
                req_type: StatsReqType::Flow,
                flags: 0,
                body: StatsReqBody::FlowStatsBody {
                    pattern: Pattern::match_all(),
                    table_id: ALL_TABLES,
                    out_port: OfpPort::OFPPNone as u16
                }
            }
        }

        fn flow_stats_reply() -> StatsResp {
            StatsResp {
                req_type: StatsReqType::Flow,
                flags: 0,
                body: StatsRespBody::FlowStatsBody {
                    flow_stats: flow_stats_vec()
                }
            }
        }

        fn flow_stats_vec() -> Vec<FlowStats> {
            let mut vec = vec!();
            let mut actions = Vec::new();
            actions.push(Action::Output(PseudoPort::Controller(0)));
            vec.push(FlowStats {
                table_id: 0,
                pattern: Pattern::match_all(),
                duration_sec: 120,
                duration_nsec: 123456789,
                priority: 33,
                idle_timeout: 0,
                hard_timeout: 0,
                cookie: 0x12345678,
                packet_count: 5000,
                byte_count: 640000,
                actions: actions
            });

            vec.push(FlowStats {
                table_id: 0,
                pattern: Pattern::match_all(),
                duration_sec: 10,
                duration_nsec: 0,
                priority: 65,
                idle_timeout: 500,
                hard_timeout: 0,
                cookie: 0x87654321,
                packet_count: 10,
                byte_count: 10000,
                actions: flow_mod_actions()
            });
            vec
        }

        fn load_reference(filepath: &str) -> Vec<u8> {
            let mut f = File::open(filepath)
                .expect("Could not find sample file");
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer).expect("Failed to read sample file");

            buffer
        }

        fn parse(data: Vec<u8>) -> (OfpHeader, Message) {
            let (header, tail) = data.split_at(OfpHeader::size());

            let ofp_header = OfpHeader::parse(header);
            let (payload, _) = tail.split_at(ofp_header.length() - OfpHeader::size());

            let (_xid, ofp_message) = Message0x01::parse(&ofp_header, payload).unwrap();
            (ofp_header, ofp_message.inner)
        }

        fn verify_header(header: &OfpHeader) {
            assert_eq!(header.version(), 1);
            assert_eq!(header.xid(), TEST_XID);
        }

        #[test]
        fn test_marshal_hello() {
            let hello = Message::Hello;
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(hello));
            let reference = load_reference(&"test/data/hello10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_hello() {
            let reference = load_reference(&"test/data/hello10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::Hello => {},
                _ => {
                    assert!(false, "Should be a Hello message");
                }
            }
        }

        #[test]
        #[ignore] // TODO marshaling error not implemented
        fn test_marshal_error() {
            let error = Message::Error(
                Error::Error(
                    ErrorType::BadRequest(BadRequest::BadLen), error_vector()));
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(error));
            let reference = load_reference(&"test/data/error10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_error() {
            let reference = load_reference(&"test/data/error10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::Error(Error::Error(
                                   ErrorType::BadRequest(BadRequest::BadLen), error_data)) => {
                    assert_eq!(error_vector(), error_data);
                },
                _ => {
                    assert!(false, "Should be a BadRequest::BadType Error message");
                }
            }
        }

        #[test]
        fn test_marshal_echo_request() {
            let echo = Message::EchoRequest(echo_vector());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(echo));
            let reference = load_reference(&"test/data/echo10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_echo_request() {
            let reference = load_reference(&"test/data/echo10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::EchoRequest(data) => {
                    assert_eq!(echo_vector(), data);
                },
                _ => {
                    assert!(false, "Should be an EchoRequest message");
                }
            }
        }

        #[test]
        fn test_marshal_echo_reply() {
            let echo = Message::EchoReply(echo_vector());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(echo));
            let reference = load_reference(&"test/data/echo_reply10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_echo_reply() {
            let reference = load_reference(&"test/data/echo_reply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::EchoReply(data) => {
                    assert_eq!(echo_vector(), data);
                },
                _ => {
                    assert!(false, "Should be an EchoReply message");
                }
            }
        }

        #[test]
        fn test_marshal_features_request() {
            let echo = Message::FeaturesReq;
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(echo));
            let reference = load_reference(&"test/data/features_request10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        #[ignore] // Not implemented
        fn test_parse_features_request() {
            let reference = load_reference(&"test/data/features_request10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::FeaturesReq => {},
                _ => {
                    assert!(false, "Should be an Features Request message");
                }
            }
        }

        #[test]
        #[ignore] // Not implemented
        fn test_marshal_features_reply() {
            let features = Message::FeaturesReply(switch_features());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/features_reply10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_features_reply() {
            let reference = load_reference(&"test/data/features_reply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::FeaturesReply(features) => {
                    assert_eq!(switch_features(), features);
                },
                _ => {
                    assert!(false, "Should be a Features Reply message");
                }
            }
        }

        #[test]
        fn test_marshal_flow_mod() {
            let features = Message::FlowMod(flow_mod());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/flowmod10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_flow_mod() {
            let reference = load_reference(&"test/data/flowmod10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::FlowMod(f) => {
                    assert_eq!(flow_mod(), f);
                },
                _ => {
                    assert!(false, "Should be a Flow Mod message");
                }
            }
        }

        #[test]
        fn test_marshal_packet_in() {
            let features = Message::PacketIn(packet_in());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/packetin10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_packet_in() {
            let reference = load_reference(&"test/data/packetin10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::PacketIn(packet) => {
                    assert_eq!(packet_in(), packet);
                },
                _ => {
                    assert!(false, "Should be a PacketIn message");
                }
            }
        }

        #[test]
        fn test_marshal_packet_out() {
            let features = Message::PacketOut(packet_out());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/packetout10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_packet_out() {
            let reference = load_reference(&"test/data/packetout10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::PacketOut(packet) => {
                    assert_eq!(packet_out(), packet);
                },
                _ => {
                    assert!(false, "Should be a PacketOut message");
                }
            }
        }

        #[test]
        fn test_marshal_barrier_request() {
            let features = Message::BarrierRequest;
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/barrierrequest10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_barrier_request() {
            let reference = load_reference(&"test/data/barrierrequest10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::BarrierRequest => {},
                _ => {
                    assert!(false, "Should be a BarrierRequest message");
                }
            }
        }

        #[test]
        fn test_marshal_barrier_reply() {
            let features = Message::BarrierReply;
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/barrierreply10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_barrier_reply() {
            let reference = load_reference(&"test/data/barrierreply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::BarrierReply => {},
                _ => {
                    assert!(false, "Should be a BarrierReply message");
                }
            }
        }

        #[test]
        fn test_marshal_flow_removed() {
            let features = Message::FlowRemoved(flow_removed());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/flowremoved10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_flow_removed() {
            let reference = load_reference(&"test/data/flowremoved10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::FlowRemoved(flow_removed_data) => {
                    assert_eq!(flow_removed(), flow_removed_data)
                },
                _ => {
                    assert!(false, "Should be a FlowRemoved message");
                }
            }
        }

        #[test]
        #[ignore]
        fn test_marshal_port_status() {
            let features = Message::PortStatus(port_status());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/portstatus10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        fn test_parse_port_status() {
            let reference = load_reference(&"test/data/portstatus10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::PortStatus(port_status_data) => {
                    assert_eq!(port_status(), port_status_data)
                },
                _ => {
                    assert!(false, "Should be a PortStatus message");
                }
            }
        }

        #[test]
        fn test_marshal_port_stats_request() {
            let features = Message::StatsRequest(port_stats_request());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/portstatsrequest10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        #[ignore]
        fn test_parse_port_stats_request() {
            let reference = load_reference(&"test/data/portstatsrequest10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsRequest(stats_request_data) => {
                    assert_eq!(port_stats_request(), stats_request_data)
                },
                _ => {
                    assert!(false, "Should be a Port StatsRequest message");
                }
            }
        }

        #[test]
        fn test_marshal_desc_stats_request() {
            let features = Message::StatsRequest(desc_stats_request());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/descstatsrequest10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        #[ignore]
        fn test_parse_desc_stats_request() {
            let reference = load_reference(&"test/data/descstatsrequest10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsRequest(stats_request_data) => {
                    assert_eq!(desc_stats_request(), stats_request_data)
                },
                _ => {
                    assert!(false, "Should be a Desc StatsRequest message");
                }
            }
        }

        #[test]
        fn test_marshal_flow_stats_request() {
            // The match-all flow stats request here has some details. It sets all fields
            // individually to be wildcards but could just set all to 1s. The sample file was
            // adapted to this strategy but was verified to be valid. There are multiple correct
            // answers to this particular flow stats request.
            let features = Message::StatsRequest(flow_stats_request());
            let data = Message0x01::marshal(TEST_XID, Message0x01::from(features));
            let reference = load_reference(&"test/data/flowstatsrequest10.data");

            assert_eq!(reference, data.unwrap());
        }

        #[test]
        #[ignore]
        fn test_parse_flow_stats_request() {
            let reference = load_reference(&"test/data/flowstatsrequest10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsRequest(stats_request_data) => {
                    assert_eq!(flow_stats_request(), stats_request_data)
                },
                _ => {
                    assert!(false, "Should be a Flow StatsRequest message");
                }
            }
        }

        #[test]
        fn test_parse_port_stats_reply() {
            let reference = load_reference(&"test/data/portstatsreply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsReply(stats_reply_data) => {
                    assert_eq!(port_stats_reply(), stats_reply_data)
                },
                _ => {
                    assert!(false, "Should be a Port StatsReply message");
                }
            }
        }

        #[test]
        fn test_parse_desc_stats_reply() {
            let reference = load_reference(&"test/data/descstatsreply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsReply(stats_reply_data) => {
                    assert_eq!(desc_stats_reply(), stats_reply_data)
                },
                _ => {
                    assert!(false, "Should be a Desc StatsReply message");
                }
            }
        }

        #[test]
        fn test_parse_flow_stats_reply() {
            let reference = load_reference(&"test/data/flowstatsreply10.data");
            let (header, message) = parse(reference);

            verify_header(&header);
            match message {
                Message::StatsReply(stats_reply_data) => {
                    assert_eq!(flow_stats_reply(), stats_reply_data)
                },
                _ => {
                    assert!(false, "Should be a Flow StatsReply message");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_serialization() {
        let mask = 8;
        let data = 0;
        let serialized = Wildcards0x01::set_nw_mask(data, 14, mask);
        let deserialized = Wildcards0x01::get_nw_mask(serialized, 14);

        assert_eq!(mask, deserialized);
    }
}