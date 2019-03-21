
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

/// How long before a flow entry expires.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Timeout {
    Permanent,
    ExpiresAfter(u16),
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
    pub stp: bool,
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

/// Switch features.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchFeatures {
    pub datapath_id: u64,
    pub num_buffers: u32,
    pub num_tables: u8,
    pub supported_capabilities: Capabilities,
    pub supported_actions: SupportedActions,
    pub ports: Vec<PortDesc>,
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

/// Represents modifications to a flow table from the controller.
#[derive(Debug, PartialEq)]
pub struct FlowMod {
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
    FlowStatsBody { // Also used for aggregate stats
    pattern: Pattern,
        table_id: u8,
        out_port: u16
    },
    TableBody,
    PortBody {
        port_no: u16,
    },
    QueueBody {
        port_no: u16,
        queue_id: u32,
    },
    VendorBody
}

/// Represents stats request from the controller.
#[derive(Debug, PartialEq)]
pub struct StatsReq {
    // TODO we shouldn't need the type, it can be inferred by the body
    pub req_type: StatsReqType,
    pub flags: u16,
    pub body: StatsReqBody
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
    pub actions: Vec<Action>
}

#[derive(Debug, PartialEq, Clone)]
pub struct TransmissionCounter {
    pub rx: u64,
    pub tx: u64
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
    pub collisions: u64
}

#[derive(Debug, PartialEq)]
pub struct QueueStats {
    pub port_no: u16,
    pub queue_id: u32,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64
}

#[derive(Debug, PartialEq)]
pub struct TableStats {
    pub table_id: u8,
    pub name: String,
    pub wildcards: Wildcards,
    pub max_entries: u32,
    pub active_count: u32,
    pub lookup_count: u64,
    pub matched_count: u64
}

/// Type of Body for Stats Response
#[derive(Debug, PartialEq)]
pub enum StatsRespBody {
    DescBody {
        manufacturer_desc: String,
        hardware_desc: String,
        software_desc: String,
        serial_number: String,
        datapath_desc: String
    },
    FlowStatsBody {
        flow_stats: Vec<FlowStats>
    },
    AggregateStatsBody {
        packet_count: u64,
        byte_count: u64,
        flow_count: u32,
    },
    TableBody {
        table_stats: Vec<TableStats>
    },
    PortBody {
        port_stats: Vec<PortStats>
    },
    QueueBody {
        queue_stats: Vec<QueueStats>
    },
    VendorBody
}

#[derive(Debug, PartialEq)]
pub struct StatsResp {
    pub req_type: StatsReqType, // TODO not required because of the body enum representing the type
    pub flags: u16,
    pub body: StatsRespBody
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
    StatsReply(StatsResp)
}