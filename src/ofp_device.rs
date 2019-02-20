use rust_ofp::ofp_message::OfpMessage;

const WRITING_CHANNEL_SIZE: usize = 1000;

/// OpenFlow Device
///
/// Version-agnostic API for communicating with an OpenFlow Device.
pub trait OfpDevice {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the device.
    fn send_message(&self, xid: u32, message: Self::Message);

    /// Handle a message from the device
    fn process_message(&self, xid: u32, message: Self::Message);
}

pub mod openflow0x01 {
    use super::*;

    use std::fmt;

    use tokio::io;
    use tokio::net::TcpStream;
    use tokio::prelude::*;

    use futures::sync::mpsc;
    use futures::sync::mpsc::{Receiver, Sender};

    use bytes::BytesMut;

    use rust_ofp::ofp_header::OfpHeader;
    use rust_ofp::ofp_message::OfpMessage;
    use rust_ofp::openflow0x01::message::Message;
    use std::sync::Mutex;
    use std::sync::Arc;
    use std::collections::HashMap;
    use openflow0x01::{ PacketIn, StatsResp, StatsRespBody, PortStats, FlowStats, TableStats, QueueStats };
    use tokio::io::{ ReadHalf, WriteHalf };

    #[derive(Debug)]
    struct DeviceState {
        switch_id: Option<DeviceId>,
    }

    impl DeviceState {
        fn new() -> DeviceState {
            DeviceState {
                switch_id: None,
            }
        }

        pub fn has_device_id(&self, device_id: &DeviceId) -> bool {
            match &self.switch_id {
                Some(ref id) => id == device_id,
                None => false
            }
        }

        pub fn get_device_id(&self) -> Option<DeviceId> {
            return self.switch_id.clone();
        }
    }

    struct MessageProcessor {
        state: Arc<Mutex<DeviceState>>,
        tx: Sender<(DeviceId, Message)>,
        writer: Sender<(u32, Message)> // TODO define a xid type
    }

    impl MessageProcessor {
        fn new(state: Arc<Mutex<DeviceState>>,
               tx: Sender<(DeviceId, Message)>,
               writer: Sender<(u32, Message)>) -> MessageProcessor {
            MessageProcessor {
                state,
                tx,
                writer
            }
        }

        fn send_message(&mut self, xid: u32, message: Message) {
            self.writer.try_send((xid, message)).unwrap();
        }

        fn process_message(&mut self, xid: u32, message: Message) {
            match &message {
                Message::Hello => {
                    info!("Received Hello message, sending a Features Req");
                    self.send_message(xid, Message::FeaturesReq);
                },
                Message::Error(err) => println!("Error: {:?}", err),
                Message::EchoRequest(ref bytes) => {
                    self.send_message(xid, Message::EchoReply(bytes.clone()))
                }
                Message::EchoReply(_) => (),
                Message::FeaturesReq => (),
                Message::FeaturesReply(feats) => {
                    let mut state = self.state.lock().unwrap();
                    if state.switch_id.is_some() {
                        panic!("Switch connection already received.")
                    }

                    state.switch_id = Some(DeviceId(feats.datapath_id));
                }
                Message::FlowMod(_) |
                Message::PacketIn(_) |
                Message::StatsReply(_) |
                Message::FlowRemoved(_) |
                Message::PortStatus(_) |
                Message::PacketOut(_) |
                Message::BarrierRequest |
                Message::BarrierReply |
                Message::StatsRequest(_) => (),
            }

            // TODO do we need to lock every time only for reading? There might be a better way.
            let state = self.state.lock().unwrap();
            match state.switch_id {
                Some(ref switch_id) => {
                    self.tx.try_send((switch_id.clone(), message)).unwrap();
                },
                None => {
                    // TODO log?
                }
            }
        }
    }

    pub struct Device {
        state: Arc<Mutex<DeviceState>>,
        processor: Arc<Mutex<MessageProcessor>>,

        writer: Mutex<Sender<(u32, Message)>>,
    }

    impl OfpDevice for Device {
        type Message = Message;

        fn send_message(&self, xid: u32, message: Message) {
            let mut writer = self.writer.lock().unwrap();
            writer.try_send((xid, message)).unwrap(); // TODO handle errors
        }

        fn process_message(&self, xid: u32, message: Message) {
            let mut processor = self.processor.lock().unwrap();
            processor.process_message(xid, message);
        }
    }

    impl Device {
        pub fn new(stream: TcpStream, tx: Sender<(DeviceId, Message)>) -> Device {
            let (read, write) = stream.split();

            let (writer_tx, writer_rx) = mpsc::channel(WRITING_CHANNEL_SIZE);
            let writer = OfpMessageWriter::new(write, writer_rx);
            let state = Arc::new(Mutex::new(DeviceState::new()));
            let processor = Arc::new(Mutex::new(MessageProcessor::new(state.clone(), tx, writer_tx.clone())));

            let reader = OfpMessageReader::new(read);
            tokio::spawn(writer);
            tokio::spawn(DeviceFuture::new(processor.clone(), reader));

            Device {
                state,
                writer: Mutex::new(writer_tx),
                processor
            }
        }

        pub fn has_device_id(&self, device_id: &DeviceId) -> bool {
            let state = self.state.lock().unwrap();
            state.has_device_id(device_id)
        }

        pub fn get_device_id(&self) -> Option<DeviceId> {
            let state = self.state.lock().unwrap();
            state.get_device_id()
        }
    }

    struct DeviceFuture {
        processor: Arc<Mutex<MessageProcessor>>,
        reader: OfpMessageReader,
    }

    impl DeviceFuture {
        fn new(processor: Arc<Mutex<MessageProcessor>>, reader: OfpMessageReader) -> DeviceFuture {
            DeviceFuture {
                reader,
                processor,
            }
        }
    }

    // TODO Optimize this to use the MessageProcessor directly
    impl Future for DeviceFuture {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
            const MESSAGES_PER_TICK: usize = 10;
            for _ in 0..MESSAGES_PER_TICK {
                let res = self.reader.poll();
                match res {
                    Ok(Async::Ready(Some((header, message)))) => {
                        let mut processor = self.processor.lock().unwrap();
                        processor.process_message(header.xid(), message);
                    },
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady)
                    },
                    Ok(Async::Ready(None)) => {
                        info!("Device disconnected");
                        return Ok(Async::Ready(()))
                    },
                    Err(e) => {
                        error!("Error on device stream reader: {:?}", e);
                        panic!("Error on reader: {}", e); // TODO
                    }
                }
            }

            task::current().notify();
            Ok(Async::NotReady)
        }
    }

    #[derive(Debug)]
    struct OfpMessageReader {
        socket: ReadHalf<TcpStream>,
        rd: BytesMut
    }

    impl OfpMessageReader {
        pub fn new(socket: ReadHalf<TcpStream>) -> Self {
            OfpMessageReader {
                socket,
                rd: BytesMut::new(),
            }
        }

        fn have_full_message(&self) -> bool {
            if self.have_header() {
                return self.rd.len() >= self.get_header_length();
            }
            false
        }

        fn have_header(&self) -> bool {
            self.rd.len() >= OfpHeader::size()
        }

        fn read_message_data(&mut self) -> Poll<(), io::Error> {
            loop {
                if self.have_full_message() {
                    return Ok(Async::Ready(()));
                } else if self.have_header() {
                    try_ready!(self.read_body());
                } else {
                    try_ready!(self.read_header());
                }
            }
        }

        fn read_header(&mut self) -> Poll<(), io::Error> {
            self.rd.reserve(OfpHeader::size());

            // Read data into the buffer.
            let _n = try_ready!(self.socket.read_buf(&mut self.rd));
            if self.have_header() {
                Ok(Async::Ready(()))
            } else {
                Ok(Async::NotReady)
            }
        }

        fn read_body(&mut self) -> Poll<(), io::Error> {
            assert!(self.have_header());
            let length = self.get_header_length();
            self.read_data(length)
        }

        fn read_data(&mut self, length: usize) -> Poll<(), io::Error> {
            self.rd.reserve(length);
            loop {
                let _n = try_ready!(self.socket.read_buf(&mut self.rd));
                if self.have_full_message() {
                    return Ok(Async::Ready(()));
                }
            }
        }

        fn get_header_length(&self) -> usize {
            let len_1 = *self.rd.get(2).unwrap() as usize;
            let len_2 = *self.rd.get(3).unwrap() as usize;

            return (len_1 << 8) + len_2
        }

        fn parse_message(&mut self) -> io::Result<(OfpHeader, Message)> {
            let body_length = self.get_header_length() - OfpHeader::size();
            let header_data = self.rd.split_to(OfpHeader::size());
            let data = self.rd.split_to(body_length);

            let header = OfpHeader::parse(&header_data);
            let (_xid, body) = Message::parse(&header, &data);
            Ok((header, body))
        }
    }

    impl Stream for OfpMessageReader {
        type Item = (OfpHeader, Message);
        type Error = io::Error;

        fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
            let res = self.read_message_data();
            match res {
                Ok(Async::NotReady) => {
                    Ok(Async::NotReady)
                },
                Ok(Async::Ready(())) => {
                    if self.have_full_message() {
                        let message = self.parse_message()?;
                        Ok(Async::Ready(Some(message)))
                    } else {
                        info!("Reading stream ended");
                        Ok(Async::Ready(None))
                    }
                },
                Err(e) => {
                    panic!("Failed to read message: {:?}", e);
                }
            }
        }
    }

    struct OfpMessageWriter {
        socket:  WriteHalf<TcpStream>,
        rx: Receiver<(u32, Message)>,
        message: Option<Vec<u8>>
    }

    impl OfpMessageWriter {
        fn new(socket: WriteHalf<TcpStream>, rx: Receiver<(u32, Message)>) -> OfpMessageWriter {
            OfpMessageWriter {
                socket,
                rx,
                message: None
            }
        }

        fn send_current_message(&mut self) -> Poll<(), ()> {
            let message = self.message.take();
            match message {
                Some(bytes) => {
                    let write_result = self.socket.poll_write(&bytes);
                    match write_result {
                        Ok(Async::NotReady) => {
                            self.message.replace(bytes);
                            Ok(Async::NotReady)
                        },
                        Ok(Async::Ready(written)) => {
                            if written != bytes.len() {
                                panic!("Sender: Could not write all data"); // TODO
                            }
                            Ok(Async::Ready(()))
                        },
                        Err(e) => {
                            match e.kind() {
                                io::ErrorKind::BrokenPipe => {
                                    Ok(Async::Ready(()))
                                },
                                _ => {
                                    panic!("Sender: Error writing to socket: {:?}", e); // TODO
                                }
                            }
                        }
                    }
                },
                None => {
                    Ok(Async::Ready(()))
                }
            }
        }
    }

    impl Future for OfpMessageWriter {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
            try_ready!(self.send_current_message());

            const MESSAGES_PER_TICK: usize = 10;
            for _ in 0..MESSAGES_PER_TICK {
                let mut res = try_ready!(self.rx.poll());
                match res {
                    Some((xid, message)) => {
                        let raw_msg = Message::marshal(xid, message);
                        self.message.replace(raw_msg);
                        try_ready!(self.send_current_message());
                    },
                    None => {
                        return Ok(Async::Ready(()));
                    }
                }
            }
            Ok(Async::NotReady)
        }
    }

    #[derive(Debug, Clone, Hash, Eq, PartialEq)]
    pub struct DeviceId(u64);

    impl fmt::Display for DeviceId {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "DeviceId({})", self.0)
        }
    }

    struct Devices {
        unknown_devices: Vec<Arc<Device>>,
        devices: HashMap<DeviceId, Arc<Device>>
    }

    impl Devices {
        fn new() -> Devices {
            Devices {
                unknown_devices: Vec::new(),
                devices: HashMap::new()
            }
        }

        fn add_device(&mut self, device: Arc<Device>) {
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
                }
                _ => {
                }
            }
        }

        fn send_message(&self, device_id: &DeviceId, xid: u32, message: Message) {
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

        fn create_device(&self, stream: TcpStream) -> Arc<Device> {
            let mut devices = self.devices.lock().unwrap();
            let device = Arc::new(Device::new(stream, self.message_tx.clone()));
            devices.add_device(device.clone());
            device
        }

        pub fn list_all_devices(&self) -> Vec<DeviceId> {
            self.devices.lock().unwrap().list_all_devices()
        }

        pub fn register_device(&self, stream: TcpStream) {
            let device = self.create_device(stream);
            device.send_message(0, Message::Hello);
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

        pub fn send_message(&self, device_id: &DeviceId, xid: u32, message: Message) {
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
}
