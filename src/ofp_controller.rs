use tokio::net::TcpStream;
use tokio::prelude::*;

use futures::sync::mpsc;
use futures::sync::mpsc::{Receiver, Sender};

use ofp_header::Xid;
use rust_ofp::ofp_device::openflow0x01::Device;
use rust_ofp::ofp_device::{ OfpDevice, DeviceId };
use rust_ofp::openflow0x01::message::Message;
use std::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use openflow0x01::{ PacketIn, StatsResp, StatsRespBody, PortStats, FlowStats, TableStats, QueueStats };

struct Devices {
    unknown_devices: Vec<Device>,
    devices: HashMap<DeviceId, Device>
}

impl Devices {
    fn new() -> Devices {
        Devices {
            unknown_devices: Vec::new(),
            devices: HashMap::new()
        }
    }

    fn add_device(&mut self, device: Device) {
        self.unknown_devices.push(device);
    }

    fn list_all_devices(&self) -> Vec<DeviceId> {
        self.devices.keys().map(|d| d.clone()).collect()
    }

    fn find_unknown_device_index(&self, dpid: &DeviceId) -> Option<usize> {
        self.unknown_devices.iter().enumerate()
            .find(|&dev| dev.1.has_device_id(dpid))
            .map(|r| r.0)
    }

    fn handle_switch_connected(&mut self, dpid: DeviceId) {
        // move the element from unknown to known devices
        let device = self.find_unknown_device_index(&dpid);

        match device {
            Some(index) => {
                let device = self.unknown_devices.remove(index);
                match device.get_device_id() {
                    Some(dpid) => {
                        self.devices.insert(dpid, device);
                    },
                    None => {
                        warn!("Tried to insert a device without a known id");
                    }
                }
            },
            None => {
                warn!("Couldn't find device with dpid {}", dpid);
            }
        }
    }

    pub fn event(&mut self, event: &DeviceControllerEvent) {
        match event {
            DeviceControllerEvent::SwitchConnected(device_id) => {
                self.handle_switch_connected(device_id.clone());
            },
            _ => {
            }
        }
    }

    fn send_message(&self, device_id: &DeviceId, xid: Xid, message: Message) {
        let device = self.devices.get(device_id);
        match device {
            Some(d) => d.send_message(xid, message),
            None => {
                warn!("Could not find device with id {}", device_id);
            }
        }
    }
}

pub trait DeviceControllerApp {
    fn event(&mut self, event: Arc<DeviceControllerEvent>);

    fn start(&mut self) {
        // Default implementation is empty
    }
}

struct DeviceControllerApps {
    apps: Vec<Box<DeviceControllerApp + Sync + Send>>
}

impl DeviceControllerApps {
    pub fn new() -> DeviceControllerApps {
        DeviceControllerApps {
            apps: Vec::new()
        }
    }

    pub fn start(&mut self) {
        for app in &mut self.apps {
            app.start();
        }
    }

    fn post(&mut self, event: DeviceControllerEvent) {
        let event = Arc::new(event);

        for app in &mut self.apps {
            // TODO Revisit this. Should we call it on a loop or spawn tasks?
            app.event(event.clone());
        }
    }

    pub fn register_app(&mut self, app: Box<DeviceControllerApp+ Sync + Send>) {
        self.apps.push(app);
    }
}

pub struct DeviceController {
    devices: Mutex<Devices>,
    message_rx: Mutex<Receiver<(DeviceId, Message)>>,
    message_tx: Sender<(DeviceId, Message)>,

    apps: Mutex<DeviceControllerApps>
}

const MESSAGES_CHANNEL_BUFFER: usize = 1000;
impl DeviceController {
    pub fn new() -> DeviceController {
        let (tx, rx) = mpsc::channel(MESSAGES_CHANNEL_BUFFER);
        DeviceController {
            devices: Mutex::new(Devices::new()),
            message_rx: Mutex::new(rx),
            message_tx: tx,
            apps: Mutex::new(DeviceControllerApps::new())
        }
    }

    pub fn start(&self) {
        self.apps.lock().unwrap().start();
    }

    fn create_device(&self, stream: TcpStream) -> Sender<(Xid, Message)> {
        let mut devices = self.devices.lock().unwrap();
        let device = Device::new(stream, self.message_tx.clone());
        let writer = device.get_writer();
        devices.add_device(device);
        writer
    }

    pub fn list_all_devices(&self) -> Vec<DeviceId> {
        self.devices.lock().unwrap().list_all_devices()
    }

    pub fn register_device(&self, stream: TcpStream) {
        let mut device_writer = self.create_device(stream);
        // TODO handle a future properly here to ensure Hello is sent
        device_writer.try_send((0, Message::Hello)).unwrap();
    }

    pub fn register_app(&self, app: Box<DeviceControllerApp + Send + Sync>) {
        let mut apps = self.apps.lock().unwrap();
        apps.register_app(app);
    }

    fn handle_event_internally(&self, event: &DeviceControllerEvent) {
        let mut devices = self.devices.lock().unwrap();
        devices.event(event);
    }

    fn post(&self, event: DeviceControllerEvent) {
        self.handle_event_internally(&event);
        let mut apps = self.apps.lock().unwrap();
        apps.post(event);
    }

    pub fn send_message(&self, device_id: &DeviceId, xid: Xid, message: Message) {
        let devices = self.devices.lock().unwrap();
        devices.send_message(device_id, xid, message);
    }
}

pub enum DeviceControllerEvent {
    SwitchConnected(DeviceId),
    PortStats(DeviceId, Vec<PortStats>),
    FlowStats(DeviceId, Vec<FlowStats>),
    TableStats(DeviceId, Vec<TableStats>),
    QueueStats(DeviceId, Vec<QueueStats>),
    AggregateStats(DeviceId, u64, u64, u32),
    PacketIn(DeviceId, PacketIn)
}

pub struct DeviceControllerFuture {
    controller: Arc<DeviceController>
}

impl DeviceControllerFuture {
    pub fn new(controller: Arc<DeviceController>) -> DeviceControllerFuture {
        DeviceControllerFuture {
            controller
        }
    }

    fn handle_stats(&self, device_id: DeviceId, stats: StatsResp) {
        match stats.body {
            StatsRespBody::DescBody{ .. } => {
            },
            StatsRespBody::PortBody{ port_stats } => {
                self.controller.post(DeviceControllerEvent::PortStats(device_id, port_stats));
            },
            StatsRespBody::TableBody{ table_stats } => {
                self.controller.post(DeviceControllerEvent::TableStats(device_id, table_stats));
            },
            StatsRespBody::AggregateStatsBody{ packet_count, byte_count, flow_count } => {
                // TODO improve this. Need to track the request to make the response make
                // sense.
                self.controller.post(DeviceControllerEvent::AggregateStats(device_id, packet_count, byte_count, flow_count));
            },
            StatsRespBody::FlowStatsBody{ flow_stats } => {
                self.controller.post(DeviceControllerEvent::FlowStats(device_id, flow_stats));
            },
            StatsRespBody::QueueBody{ queue_stats } => {
                self.controller.post(DeviceControllerEvent::QueueStats(device_id, queue_stats));
            },
            StatsRespBody::VendorBody => {
            },
        }
    }

    fn handle_message(&self, device_id: DeviceId, message: Message) {
        match message {
            Message::FeaturesReply(_feats) => {
                self.controller.post(DeviceControllerEvent::SwitchConnected(device_id));
            },
            Message::StatsReply(stats) => {
                self.handle_stats(device_id, stats);
            }
            Message::PacketIn(pkt) => {
                self.controller.post(DeviceControllerEvent::PacketIn(device_id, pkt));
            }
            _ => (),
        }
    }
}

impl Future for DeviceControllerFuture {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        const MESSAGES_PER_TICK: usize = 10;
        let mut rx = self.controller.message_rx.lock().unwrap();
        for _ in 0..MESSAGES_PER_TICK {
            match try_ready!(rx.poll()) {
                Some((device_id, message)) => {
                    self.handle_message(device_id, message);
                },
                None => {
                    return Ok(Async::Ready(()));
                }
            }
        }

        // Make sure we are rescheduled
        task::current().notify();
        Ok(Async::NotReady)
    }
}
