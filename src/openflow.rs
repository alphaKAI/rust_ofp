use std::fmt::{Display, Error, Formatter};

/// OpenFlow message type codes, used by headers to identify meaning of the rest of a message.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgCode {
    Hello,
    Error,
    EchoReq,
    EchoResp,
    Experimenter,
    FeaturesReq,
    FeaturesResp,
    GetConfigReq,
    GetConfigResp,
    SetConfig,
    PacketIn,
    FlowRemoved,
    PortStatus,
    PacketOut,
    FlowMod,
    GroupMod,
    PortMod,
    TableMod,
    MultipartReq,
    MultipartResp,
    BarrierReq,
    BarrierResp,
    QueueGetConfigReq,
    QueueGetConfigResp,
    RoleReq,
    RoleResp,
    GetAsyncReq,
    GetAsyncResp,
    SetAsync,
    MeterMod,

    // 1.0
    Vendor,
    StatsReq,
    StatsResp,
}

impl Display for MsgCode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let text = match self {
            MsgCode::Hello => "Hello",
            MsgCode::Error => "Error",
            MsgCode::EchoReq => "EchoReq",
            MsgCode::EchoResp => "EchoResp",
            MsgCode::Vendor => "Vendor",
            MsgCode::FeaturesReq => "FeaturesReq",
            MsgCode::FeaturesResp => "FeaturesResp",
            MsgCode::GetConfigReq => "GetConfigReq",
            MsgCode::GetConfigResp => "GetConfigResp",
            MsgCode::SetConfig => "SetConfig",
            MsgCode::PacketIn => "PacketIn",
            MsgCode::FlowRemoved => "FlowRemoved",
            MsgCode::PortStatus => "PortStatus",
            MsgCode::PacketOut => "PacketOut",
            MsgCode::FlowMod => "FlowMod",
            MsgCode::PortMod => "PortMod",
            MsgCode::StatsReq => "StatsReq",
            MsgCode::StatsResp => "StatsResp",
            MsgCode::BarrierReq => "BarrierReq",
            MsgCode::BarrierResp => "BarrierResp",
            MsgCode::QueueGetConfigReq => "QueueGetConfigReq",
            MsgCode::QueueGetConfigResp => "QueueGetConfigResp",
            MsgCode::Experimenter => "Experimenter",
            MsgCode::GroupMod => "GroupMod",
            MsgCode::TableMod => "TableMod",
            MsgCode::MultipartReq => "MultipartReq",
            MsgCode::MultipartResp => "MultipartResp",
            MsgCode::RoleReq => "RoleReq",
            MsgCode::RoleResp => "RoleResp",
            MsgCode::GetAsyncReq => "GetAsyncReq",
            MsgCode::GetAsyncResp => "GetAsyncResp",
            MsgCode::SetAsync => "SetAsync",
            MsgCode::MeterMod => "MeterMod",
        };
        f.write_str(text)
    }
}
