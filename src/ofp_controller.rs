use tokio::net::TcpStream;
use tokio::prelude::*;

use futures::sync::mpsc;
use futures::sync::mpsc::{Receiver, Sender};

use ofp_header::{Xid, OPENFLOW_0_01_VERSION, OPENFLOW_0_04_VERSION};
use rust_ofp::message::Message;
use rust_ofp::ofp_device::Device;
use rust_ofp::ofp_device::{DeviceEvent, DeviceId};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

const MAX_SUPPORTED_OF_VERSION: u8 = OPENFLOW_0_04_VERSION;
pub enum OfpVersion {
    _01,
    _04,
}

impl Into<u8> for OfpVersion {
    fn into(self) -> u8 {
        match self {
            Self::_01 => OPENFLOW_0_01_VERSION,
            Self::_04 => OPENFLOW_0_04_VERSION
        }
    }
}

impl From<u8> for OfpVersion {
    fn from(v: u8) -> Self {
        match v {
            OPENFLOW_0_01_VERSION => OfpVersion::_01,
            OPENFLOW_0_04_VERSION => OfpVersion::_04,
            _ => panic!("Fatal error : Specified unsupported version - {}", v)
        }
    }
}

struct Devices {
    unknown_devices: Vec<Device>,
    devices: HashMap<DeviceId, Device>,
}

impl Devices {
    fn new() -> Devices {
        Devices {
            unknown_devices: Vec::new(),
            devices: HashMap::new(),
        }
    }

    fn add_device(&mut self, device: Device) {
        self.unknown_devices.push(device);
    }

    fn list_all_devices(&self) -> Vec<DeviceId> {
        self.devices.keys().copied().collect()
    }

    fn find_unknown_device_index(&self, dpid: &DeviceId) -> Option<usize> {
        self.unknown_devices
            .iter()
            .enumerate()
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
                    }
                    None => {
                        warn!("Tried to insert a device without a known id");
                    }
                }
            }
            None => {
                warn!("Couldn't find device with dpid {}", dpid);
            }
        }
    }

    pub fn event(&mut self, event: &DeviceEvent) {
        if let DeviceEvent::SwitchConnected(device_id) = event {
            self.handle_switch_connected(*device_id);
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
    fn event(&mut self, event: Arc<DeviceEvent>);

    fn start(&mut self) {
        // Default implementation is empty
    }
}

struct DeviceControllerApps {
    apps: Vec<Box<dyn DeviceControllerApp + Sync + Send>>,
}

impl DeviceControllerApps {
    pub fn new() -> DeviceControllerApps {
        DeviceControllerApps { apps: Vec::new() }
    }

    pub fn start(&mut self) {
        for app in &mut self.apps {
            app.start();
        }
    }

    fn post(&mut self, event: DeviceEvent) {
        let event = Arc::new(event);

        for app in &mut self.apps {
            // TODO Revisit this. Should we call it on a loop or spawn tasks?
            app.event(event.clone());
        }
    }

    pub fn register_app(&mut self, app: Box<dyn DeviceControllerApp + Sync + Send>) {
        self.apps.push(app);
    }
}

pub struct DeviceController {
    devices: Mutex<Devices>,
    device_event_rx: Mutex<Receiver<DeviceEvent>>,
    device_event_tx: Sender<DeviceEvent>,

    apps: Mutex<DeviceControllerApps>,
}

const MESSAGES_CHANNEL_BUFFER: usize = 1000;
impl Default for DeviceController {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(MESSAGES_CHANNEL_BUFFER);
        DeviceController {
            devices: Mutex::new(Devices::new()),
            device_event_rx: Mutex::new(rx),
            device_event_tx: tx,
            apps: Mutex::new(DeviceControllerApps::new()),
        }
    }
}
impl DeviceController {
    pub fn start(&self) {
        self.apps.lock().unwrap().start();
    }

    fn create_device(&self, stream: TcpStream) -> Sender<(u8, Xid, Message)> {
        let mut devices = self.devices.lock().unwrap();
        let device = Device::new(stream, self.device_event_tx.clone());
        let writer = device.get_writer();
        devices.add_device(device);
        writer
    }

    pub fn list_all_devices(&self) -> Vec<DeviceId> {
        self.devices.lock().unwrap().list_all_devices()
    }

    pub fn register_device(&self, stream: TcpStream, version: Option<OfpVersion>) {
        let mut device_writer = self.create_device(stream);
        // TODO handle a future properly here to ensure Hello is sent
        device_writer
            .try_send((version.unwrap_or(MAX_SUPPORTED_OF_VERSION.into()).into(), 0, Message::Hello))
            .unwrap();
    }

    pub fn register_app(&self, app: Box<dyn DeviceControllerApp + Send + Sync>) {
        let mut apps = self.apps.lock().unwrap();
        apps.register_app(app);
    }

    fn handle_event_internally(&self, event: &DeviceEvent) {
        let mut devices = self.devices.lock().unwrap();
        devices.event(event);
    }

    fn post(&self, event: DeviceEvent) {
        self.handle_event_internally(&event);
        let mut apps = self.apps.lock().unwrap();
        apps.post(event);
    }

    pub fn send_message(&self, device_id: &DeviceId, xid: Xid, message: Message) {
        let devices = self.devices.lock().unwrap();
        devices.send_message(device_id, xid, message);
    }
}

pub struct DeviceControllerFuture {
    controller: Arc<DeviceController>,
}

impl DeviceControllerFuture {
    pub fn new(controller: Arc<DeviceController>) -> DeviceControllerFuture {
        DeviceControllerFuture { controller }
    }

    fn handle_event(&self, event: DeviceEvent) {
        self.controller.post(event);
    }
}

impl Future for DeviceControllerFuture {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        const EVENTS_PER_TICK: usize = 10;
        let mut rx = self.controller.device_event_rx.lock().unwrap();
        for _ in 0..EVENTS_PER_TICK {
            match try_ready!(rx.poll()) {
                Some(event) => {
                    self.handle_event(event);
                }
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
