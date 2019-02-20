use std::collections::HashMap;
use rust_ofp::openflow0x01::{Action, PacketIn, PacketOut, Pattern, PseudoPort};
use rust_ofp::openflow0x01::message::{add_flow, parse_payload};
use ofp_device::openflow0x01::{DeviceControllerApp, DeviceControllerEvent};
use ofp_device::openflow0x01::DeviceId;
use std::sync::Arc;
use openflow0x01::message::Message;
use openflow0x01::FlowMod;
use ofp_device::openflow0x01::DeviceController;

/// Implements L2 learning switch functionality. Switches forward packets to the
/// learning controller, which will examine the packet and learn the source-port
/// mapping. If the controller already knows the destination location, it pushes
/// a flow entry down to the switch that matches traffic between the packet's
/// source and destination.
///
/// Abstractly, a learning switch can be thought of in terms of two logically
/// distinct components.
///
///  - A _Learning Module_ that builds a map from host MAC addresses to the
///    switch port on which they are connected.
///
///  - A _Routing Module_ that performs traffic routing. If the switch receives
///    a packet which the learning module has learned of the destination location,
///    it forwards the packet directly on the associated port. If the location of
///    the destination is unknown, it floods the packet out all ports.
pub struct LearningSwitch {
    known_hosts: HashMap<u64, u16>,
    controller: Arc<DeviceController>
}

impl LearningSwitch {
    fn learning_packet_in(&mut self, pkt: &PacketIn) {
        let pk = parse_payload(&pkt.input_payload);
        self.known_hosts.insert(pk.dl_src, pkt.port);
    }

    fn routing_packet_in(&mut self, sw: &DeviceId, pkt: &PacketIn) {
        let pk = parse_payload(&pkt.input_payload);
        let pkt_dst = pk.dl_dst;
        let pkt_src = pk.dl_src;
        let out_port = self.known_hosts.get(&pkt_dst);
        match out_port {
            Some(p) => {
                let src_port = pkt.port;
                let mut src_dst_match = Pattern::match_all();
                src_dst_match.dl_dst = Some(pkt_dst);
                src_dst_match.dl_src = Some(pkt_src);
                let mut dst_src_match = Pattern::match_all();
                dst_src_match.dl_dst = Some(pkt_src);
                dst_src_match.dl_src = Some(pkt_dst);
                println!("Installing rule for host {:?} to {:?}.", pkt_src, pkt_dst);
                let actions = vec![Action::Output(PseudoPort::PhysicalPort(*p))];
                self.send_flow_mod(sw, 0, add_flow(10, src_dst_match, actions));
                println!("Installing rule for host {:?} to {:?}.", pkt_dst, pkt_src);
                let actions = vec![Action::Output(PseudoPort::PhysicalPort(src_port))];
                self.send_flow_mod(sw, 0, add_flow(10, dst_src_match, actions));
                let pkt_out = PacketOut {
                    output_payload: pkt.clone_payload(),
                    port_id: None,
                    apply_actions: vec![Action::Output(PseudoPort::PhysicalPort(*p))],
                };
                self.send_packet_out(sw, 0, pkt_out)
            }
            None => {
                println!("Flooding to {:?}", pkt_dst);
                let pkt_out = PacketOut {
                    output_payload: pkt.clone_payload(),
                    port_id: None,
                    apply_actions: vec![Action::Output(PseudoPort::AllPorts)],
                };
                self.send_packet_out(sw, 0, pkt_out)
            }
        }
    }

    pub fn new(controller: Arc<DeviceController>) -> LearningSwitch {
        LearningSwitch { known_hosts: HashMap::new(), controller }
    }

    fn packet_in(&mut self, sw: &DeviceId, pkt: &PacketIn) {
        self.learning_packet_in(&pkt);
        self.routing_packet_in(sw, pkt);
    }

    fn send_flow_mod(&self, device: &DeviceId, xid: u32, message: FlowMod) {
        self.controller.send_message(device, xid, Message::FlowMod(message));
    }

    fn send_packet_out(&self, device: &DeviceId, xid: u32, pkt: PacketOut) {
        self.controller.send_message(device, xid, Message::PacketOut(pkt));
    }
}

pub struct LearningSwitchApp {
    switch: LearningSwitch
}

impl LearningSwitchApp {
    pub fn new(controller: Arc<DeviceController>) -> LearningSwitchApp {
        LearningSwitchApp {
            switch: LearningSwitch::new(controller)
        }
    }
}

impl DeviceControllerApp for LearningSwitchApp {
    fn event(&mut self, event: Arc<DeviceControllerEvent>) {
        match *event {
            DeviceControllerEvent::PacketIn(ref device_id, ref packet) => {
                self.switch.packet_in(device_id, packet);
            },
            _ => {}
        }
    }
}
