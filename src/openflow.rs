use std::fmt::{Display, Formatter, Error};

/// OpenFlow message type codes, used by headers to identify meaning of the rest of a message.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgCode {
    Hello,
    Error,
    EchoReq,
    EchoResp,
    Vendor,
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
    PortMod,
    StatsReq,
    StatsResp,
    BarrierReq,
    BarrierResp,
    QueueGetConfigReq,
    QueueGetConfigResp,
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
        };
        f.write_str(text)
    }
}