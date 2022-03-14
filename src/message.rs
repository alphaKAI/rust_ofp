#[derive(Debug, PartialEq, Clone)]
pub struct Wildcards {
    pub in_port: bool,
    pub dl_vlan: bool,
    pub dl_src: bool,
    pub dl_dst: bool,
    pub dl_type: bool,
    pub nw_proto: bool,
    pub tp_src: bool,
    pub tp_dst: bool,
    pub nw_src: u32,
    pub nw_dst: u32,
    pub dl_vlan_pcp: bool,
    pub nw_tos: bool,
}

impl Wildcards {
    fn mask_bits(x: &Option<Mask<u32>>) -> u32 {
        match *x {
            None => 32,
            Some(ref x) => x.mask.unwrap_or(0),
        }
    }
}

/// How long before a flow entry expires.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Timeout {
    Permanent,
    ExpiresAfter(u16),
}

impl Timeout {
    pub fn of_int(tm: u16) -> Timeout {
        match tm {
            0 => Timeout::Permanent,
            d => Timeout::ExpiresAfter(d),
        }
    }

    pub fn to_int(tm: Timeout) -> u16 {
        match tm {
            Timeout::Permanent => 0,
            Timeout::ExpiresAfter(d) => d,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Mask<T> {
    pub value: T,
    pub mask: Option<T>,
}

/// Capabilities supported by the datapath.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub flow_stats: bool,
    pub table_stats: bool,
    pub port_stats: bool,
    pub group_stats: bool,
    pub stp: bool,
    pub port_blocked: bool,
    pub ip_reasm: bool,
    pub queue_stats: bool,
    pub arp_match_ip: bool,
}

/// Actions supported by the datapath.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SupportedActions {
    pub output: bool,
    pub set_vlan_id: bool,
    pub set_vlan_pcp: bool,
    pub strip_vlan: bool,
    pub set_dl_src: bool,
    pub set_dl_dst: bool,
    pub set_nw_src: bool,
    pub set_nw_dst: bool,
    pub set_nw_tos: bool,
    pub set_tp_src: bool,
    pub set_tp_dst: bool,
    pub enqueue: bool,
    pub vendor: bool,
}

// TODO this should be stored with the Device
/// Switch features.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchFeatures {
    pub datapath_id: u64,
    pub num_buffers: u32,
    pub num_tables: u8,
    pub auxiliary_id: u8,
    pub supported_capabilities: Capabilities,
    pub supported_actions: Option<SupportedActions>,
    pub ports: Option<Vec<PortDesc>>,
}

/// Fields to match against flows.
#[derive(Debug, PartialEq)]
pub struct Pattern {
    pub dl_src: Option<u64>,
    pub dl_dst: Option<u64>,
    pub dl_typ: Option<u16>,
    pub dl_vlan: Option<Option<u16>>,
    pub dl_vlan_pcp: Option<u8>,
    pub nw_src: Option<Mask<u32>>,
    pub nw_dst: Option<Mask<u32>>,
    pub nw_proto: Option<u8>,
    pub nw_tos: Option<u8>,
    pub tp_src: Option<u16>,
    pub tp_dst: Option<u16>,
    pub in_port: Option<u16>,
}

impl Pattern {
    pub fn match_all() -> Pattern {
        Pattern {
            dl_src: None,
            dl_dst: None,
            dl_typ: None,
            dl_vlan: None,
            dl_vlan_pcp: None,
            nw_src: None,
            nw_dst: None,
            nw_proto: None,
            nw_tos: None,
            tp_src: None,
            tp_dst: None,
            in_port: None,
        }
    }

    pub fn wildcards_of_pattern(m: &Pattern) -> Wildcards {
        Wildcards {
            in_port: m.in_port.is_none(),
            dl_vlan: m.dl_vlan.is_none(),
            dl_src: m.dl_src.is_none(),
            dl_dst: m.dl_dst.is_none(),
            dl_type: m.dl_typ.is_none(),
            nw_proto: m.nw_proto.is_none(),
            tp_src: m.tp_src.is_none(),
            tp_dst: m.tp_dst.is_none(),
            nw_src: Wildcards::mask_bits(&m.nw_src),
            nw_dst: Wildcards::mask_bits(&m.nw_dst),
            dl_vlan_pcp: m.dl_vlan_pcp.is_none(),
            nw_tos: m.nw_tos.is_none(),
        }
    }
}

/// Port behavior.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PseudoPort {
    PhysicalPort(u16),
    InPort,
    Table,
    Normal,
    Flood,
    AllPorts,
    Controller(u64),
    Local,
}

/// Type of modification to perform on a flow table.
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum FlowModCmd {
    AddFlow,
    ModFlow,
    ModStrictFlow,
    DeleteFlow,
    DeleteStrictFlow,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct TableId(pub u8);

impl TableId {}

/// Represents modifications to a flow table from the controller.
#[derive(Debug, PartialEq)]
pub struct FlowMod {
    pub table: TableId,
    pub command: FlowModCmd,
    pub pattern: Pattern,
    pub priority: u16,
    pub actions: Vec<Action>,
    pub cookie: u64,
    pub idle_timeout: Timeout,
    pub hard_timeout: Timeout,
    pub notify_when_removed: bool,
    pub apply_to_packet: Option<u32>,
    pub out_port: Option<PseudoPort>,
    pub check_overlap: bool,
}

/// Actions associated with flows and packets.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Action {
    Output(PseudoPort),
    SetDlVlan(Option<u16>),
    SetDlVlanPcp(u8),
    // TODO update those to use a MacAddress struct instead of bytes
    SetDlSrc(u64),
    SetDlDst(u64),
    SetNwSrc(u32),
    SetNwDst(u32),
    SetNwTos(u8),
    SetTpSrc(u16),
    SetTpDst(u16),
    Enqueue(PseudoPort, u32),
}

/// The data associated with a packet received by the controller.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Buffered(u32, Vec<u8>),
    NotBuffered(Vec<u8>),
}

impl Payload {
    pub fn size_of(payload: &Payload) -> usize {
        match *payload {
            Payload::Buffered(_, ref buf) | Payload::NotBuffered(ref buf) => buf.len(),
        }
    }
}

/// The reason a packet arrives at the controller.
#[repr(u8)]
#[derive(Debug, PartialEq, Clone)]
pub enum PacketInReason {
    NoMatch,
    ExplicitSend,
}

/// Represents packets received by the datapath and sent to the controller.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketIn {
    pub input_payload: Payload,
    pub total_len: u16,
    pub port: u16,
    pub reason: PacketInReason,
}

impl PacketIn {
    pub fn clone_payload(&self) -> Payload {
        self.input_payload.clone()
    }
}

/// Represents packets sent from the controller.
#[derive(Debug, PartialEq)]
pub struct PacketOut {
    pub output_payload: Payload,
    pub port_id: Option<u16>,
    pub apply_actions: Vec<Action>,
}

/// Reason a flow was removed from a switch
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum FlowRemovedReason {
    IdleTimeout,
    HardTimeout,
    Delete,
}

/// Flow removed (datapath -> controller)
#[derive(Debug, PartialEq)]
pub struct FlowRemoved {
    pub pattern: Pattern,
    pub cookie: i64,
    pub priority: u16,
    pub reason: FlowRemovedReason,
    pub duration_sec: u32,
    pub duration_nsec: u32,
    pub idle_timeout: Timeout,
    pub packet_count: u64,
    pub byte_count: u64,
}

/// STP state of a port.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StpState {
    Listen,
    Learn,
    Forward,
    Block,
}

/// Current state of a physical port. Not configurable by the controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortState {
    pub down: bool,
    pub stp_state: StpState,
}

/// Features of physical ports available in a datapath.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PortFeatures {
    pub f_10mbhd: bool,
    pub f_10mbfd: bool,
    pub f_100mbhd: bool,
    pub f_100mbfd: bool,
    pub f_1gbhd: bool,
    pub f_1gbfd: bool,
    pub f_10gbfd: bool,
    pub copper: bool,
    pub fiber: bool,
    pub autoneg: bool,
    pub pause: bool,
    pub pause_asym: bool,
}

/// Flags to indicate behavior of the physical port.
///
/// These flags are used both to describe the current configuration of a physical port,
/// and to configure a port's behavior.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PortConfig {
    pub down: bool,
    pub no_stp: bool,
    pub no_recv: bool,
    pub no_recv_stp: bool,
    pub no_flood: bool,
    pub no_fwd: bool,
    pub no_packet_in: bool,
}

/// Description of a physical port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortDesc {
    pub port_no: u16,
    pub hw_addr: u64,
    pub name: String,
    pub config: PortConfig,
    pub state: PortState,
    pub curr: PortFeatures,
    pub advertised: PortFeatures,
    pub supported: PortFeatures,
    pub peer: PortFeatures,
}

/// Type of stats request.
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum StatsReqType {
    Desc,
    Flow,
    Aggregate,
    Table,
    Port,
    Queue,
    Vendor = 0xFFFF,
}

/// Type of Body for Stats Requests
#[derive(Debug, PartialEq)]
pub enum StatsReqBody {
    DescBody,
    FlowStatsBody {
        // Also used for aggregate stats
        pattern: Pattern,
        table_id: u8,
        out_port: u16,
    },
    TableBody,
    PortBody {
        port_no: u16,
    },
    QueueBody {
        port_no: u16,
        queue_id: u32,
    },
    VendorBody,
}

/// Represents stats request from the controller.
#[derive(Debug, PartialEq)]
pub struct StatsReq {
    // TODO we shouldn't need the type, it can be inferred by the body
    pub req_type: StatsReqType,
    pub flags: u16,
    pub body: StatsReqBody,
}

#[derive(Debug, PartialEq)]
pub struct FlowStats {
    pub table_id: u8,
    pub pattern: Pattern,
    pub duration_sec: u32,
    pub duration_nsec: u32,
    pub priority: u16,
    pub idle_timeout: u16,
    pub hard_timeout: u16,
    pub cookie: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub actions: Vec<Action>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TransmissionCounter {
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, PartialEq)]
pub struct PortStats {
    pub port_no: u16,
    pub packets: TransmissionCounter,
    pub bytes: TransmissionCounter,
    pub dropped: TransmissionCounter,
    pub errors: TransmissionCounter,
    pub rx_frame_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub collisions: u64,
}

#[derive(Debug, PartialEq)]
pub struct QueueStats {
    pub port_no: u16,
    pub queue_id: u32,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
}

#[derive(Debug, PartialEq)]
pub struct TableStats {
    pub table_id: u8,
    pub name: String,
    pub wildcards: Wildcards,
    pub max_entries: u32,
    pub active_count: u32,
    pub lookup_count: u64,
    pub matched_count: u64,
}

/// Type of Body for Stats Response
#[derive(Debug, PartialEq)]
pub enum StatsRespBody {
    DescBody {
        manufacturer_desc: String,
        hardware_desc: String,
        software_desc: String,
        serial_number: String,
        datapath_desc: String,
    },
    FlowStatsBody {
        flow_stats: Vec<FlowStats>,
    },
    AggregateStatsBody {
        packet_count: u64,
        byte_count: u64,
        flow_count: u32,
    },
    TableBody {
        table_stats: Vec<TableStats>,
    },
    PortBody {
        port_stats: Vec<PortStats>,
    },
    QueueBody {
        queue_stats: Vec<QueueStats>,
    },
    VendorBody,
}

#[derive(Debug, PartialEq)]
pub struct StatsResp {
    pub req_type: StatsReqType, // TODO not required because of the body enum representing the type
    pub flags: u16,
    pub body: StatsRespBody,
}

/// What changed about a physical port.
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum PortReason {
    PortAdd,
    PortDelete,
    PortModify,
}

/// A physical port has changed in the datapath.
#[derive(Debug, PartialEq)]
pub struct PortStatus {
    pub reason: PortReason,
    pub desc: PortDesc,
}

/// Reason Hello failed.
#[repr(u16)]
#[derive(Debug)]
pub enum HelloFailed {
    Incompatible,
    EPerm,
}

/// Reason the controller made a bad request to a switch.
#[repr(u16)]
#[derive(Debug)]
pub enum BadRequest {
    BadVersion,
    BadType,
    BadStat,
    BadVendor,
    BadSubType,
    EPerm,
    BadLen,
    BufferEmpty,
    BufferUnknown,
}

/// Reason the controller action failed.
#[repr(u16)]
#[derive(Debug)]
pub enum BadAction {
    BadType,
    BadLen,
    BadVendor,
    BadVendorType,
    BadOutPort,
    BadArgument,
    EPerm,
    TooMany,
    BadQueue,
}

/// Reason a FlowMod from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum FlowModFailed {
    AllTablesFull,
    Overlap,
    EPerm,
    BadEmergTimeout,
    BadCommand,
    Unsupported,
}

/// Reason a PortMod from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum PortModFailed {
    BadPort,
    BadHwAddr,
}

/// Reason a queue operation from the controller failed.
#[repr(u16)]
#[derive(Debug)]
pub enum QueueOpFailed {
    BadPort,
    BadQueue,
    EPerm,
}

/// High-level type of OpenFlow error
#[derive(Debug)]
pub enum ErrorType {
    HelloFailed(HelloFailed),
    BadRequest(BadRequest),
    BadAction(BadAction),
    FlowModFailed(FlowModFailed),
    PortModFailed(PortModFailed),
    QueueOpFailed(QueueOpFailed),
}

/// Error message (datapath -> controller)
#[derive(Debug)]
pub enum Error {
    Error(ErrorType, Vec<u8>),
}

/// Abstractions of OpenFlow 1.0 messages mapping to message codes.
#[derive(Debug)]
pub enum Message {
    Hello,
    Error(Error),
    EchoRequest(Vec<u8>),
    EchoReply(Vec<u8>),
    FeaturesReq,
    FeaturesReply(SwitchFeatures),
    FlowMod(FlowMod),
    PacketIn(PacketIn),
    FlowRemoved(FlowRemoved),
    PortStatus(PortStatus),
    PacketOut(PacketOut),
    BarrierRequest,
    BarrierReply,
    StatsRequest(StatsReq),
    StatsReply(StatsResp),
}
