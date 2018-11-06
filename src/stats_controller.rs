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
use std::sync::Mutex;

fn create_port_stats_req() -> StatsReq {
    StatsReq {
        req_type: StatsReqType::Port,
        flags: 0,
        body: StatsReqBody::PortBody {
            port_no: 0xFFFF
        }
    }
}

/// Continuously probes the OF device for stats and prints them.
#[derive(Debug)]
pub struct StatsController {
    stream: Option<Arc<Mutex<TcpStream>>>,
    probing_thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl StatsController {
    fn new_empty() -> StatsController {
        StatsController {
            stream: None,
            probing_thread: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    fn negotiate(&self) {
        let real_stream = self.stream.as_ref().unwrap();
        let mut stream = real_stream.lock().unwrap();
        StatsController::handle_client_connected(&mut stream);
    }

    pub fn start(&mut self, stream: TcpStream) {
        println!("Start");
        self.stream = Some(Arc::new(Mutex::new(stream)));

        println!("Started: {:?}", self);
        self.negotiate();
    }

    fn send_stats_request(local_stream: &Arc<Mutex<TcpStream>>) {
        let mut stream = local_stream.lock().unwrap();
        let stats_request = Message::StatsRequest(create_port_stats_req());
        StatsController::send_message(0, stats_request, &mut stream);
    }
}

impl OF0x01Controller for StatsController {
    fn new() -> StatsController {
        StatsController::new_empty()
    }

    fn switch_connected(&mut self, _: u64, _: SwitchFeatures, stream: &mut TcpStream) {
        println!("Connected: {:?}", self);
        let real_stream = self.stream.as_ref().unwrap();
        let local_stream = real_stream.clone();
        let local_running = self.running.clone();
        let handle = thread::spawn(move || {
            loop {
                if !local_running.load(Ordering::Relaxed) {
                    break;
                }
                let ten_seconds = time::Duration::from_secs(10);
                thread::sleep(ten_seconds);
                println!("Sending stats request!");

                StatsController::send_stats_request(&local_stream);
            }
        });
        self.probing_thread = Some(handle);
    }

    fn switch_disconnected(&mut self, _: u64) {
    }

    fn packet_in(&mut self, sw: u64, xid: u32, pkt: PacketIn, stream: &mut TcpStream) {
    }

    fn stats(&mut self, sw: u64, xid: u32, stats: StatsResp, stream: &mut TcpStream) {
        println!("Stats");
    }
}
