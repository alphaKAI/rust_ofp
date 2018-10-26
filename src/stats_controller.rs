use std::collections::HashMap;
use std::net::TcpStream;
use std::time;
use std::thread;
use std::thread::JoinHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use rust_ofp::ofp_controller::openflow0x01::OF0x01Controller;
use rust_ofp::ofp_controller::OfpController;
use rust_ofp::openflow0x01::{Action, PacketIn, PacketOut, Pattern, PseudoPort, SwitchFeatures};
use rust_ofp::openflow0x01::message::{Message, add_flow, parse_payload};
use rust_ofp::openflow0x01::*;

fn create_port_stats_req() -> StatsReq {
    StatsReq {
        req_type: StatsReqType::Port,
        flags: 0,
        body: StatsReqBody::PortBody {
            port_no: 0
        }
    }
}

/// Continuously probes the OF device for stats and prints them.
pub struct StatsController {
    stream: TcpStream,
    inner_controller: InnerController
}

impl StatsController {
    pub fn new(stream: TcpStream) -> StatsController {
        StatsController {
            stream: stream,
            inner_controller: InnerController::new()
        }
    }

    pub fn start(&mut self) {
        InnerController::handle_client_connected(&mut self.stream);
    }
}

struct InnerController {
}

impl OF0x01Controller for InnerController {
    fn new() -> InnerController {
        InnerController{}
    }

    fn switch_connected(&mut self, _: u64, _: SwitchFeatures, stream: &mut TcpStream) {
    }

    fn switch_disconnected(&mut self, _: u64) {
    }

    fn packet_in(&mut self, sw: u64, xid: u32, pkt: PacketIn, stream: &mut TcpStream) {
    }
}
