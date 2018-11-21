use rust_ofp::ofp_message::OfpMessage;

/// OpenFlow Device
///
/// Version-agnostic API for communicating with an OpenFlow Device.
pub trait OfpDevice {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the device.
    fn send_message(&self, xid: u32, message: Self::Message);

    /// Handle a message from the device
    fn process_message(&self, xid: u32, message : Self::Message);
}

pub mod openflow0x01 {
    use super::*;

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
    use openflow0x01::PacketIn;

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
    }

    impl DeviceState {
    }

    struct MessageProcessor {
        state: Arc<Mutex<DeviceState>>,
        tx: Sender<(DeviceId, Message)>,
        writer: OfpMessageWriter
    }

    impl MessageProcessor {
        fn new(state: Arc<Mutex<DeviceState>>,
               tx: Sender<(DeviceId, Message)>,
               writer: OfpMessageWriter) -> MessageProcessor {
            MessageProcessor {
                state,
                tx,
                writer
            }
        }

        fn send_message(&mut self, xid: u32, message: Message) {
            self.writer.send_message(xid, message);
        }

        fn process_message(&mut self, xid: u32, message: Message) {
            match &message {
                Message::Hello => self.send_message(xid, Message::FeaturesReq),
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
                    //self.switch_connected(cntl, feats.datapath_id, feats)
                }
                Message::FlowMod(_) => (),
                Message::PacketIn(_pkt) => {
                    //self.packet_in(cntl, self.switch_id.unwrap(), xid, pkt)
                }
                Message::FlowRemoved(_) |
                Message::PortStatus(_) |
                Message::PacketOut(_) |
                Message::BarrierRequest |
                Message::BarrierReply => (),
            }

            // TODO do we need to lock every time only for reading? There might be a better way.
            let state = self.state.lock().unwrap();
            match state.switch_id {
                Some(ref switch_id) => {
                    self.tx.try_send((switch_id.clone(), message));
                },
                None => {
                    // TODO log?
                }
            }
        }
    }

    pub struct Device {
        state: Arc<Mutex<DeviceState>>,
        processor: Mutex<MessageProcessor>,

        writer: Mutex<OfpMessageWriter>,

        socket: TcpStream,
    }

    impl OfpDevice for Device {
        type Message = Message;

        fn send_message(&self, xid: u32, message: Message) {
            let mut writer = self.writer.lock().unwrap();
            writer.send_message(xid, message);
        }

        fn process_message(&self, xid: u32, message: Message) {
            let mut processor = self.processor.lock().unwrap();
            processor.process_message(xid, message);
        }
    }

    impl Device {
        pub fn new(stream: TcpStream, tx: Sender<(DeviceId, Message)>) -> Device {
            let writer = OfpMessageWriter::new(stream.try_clone().unwrap());
            let proc_writer = OfpMessageWriter::new(stream.try_clone().unwrap());
            let state = Arc::new(Mutex::new(DeviceState::new()));
            let processor = MessageProcessor::new(state.clone(), tx, proc_writer);
            Device {
                state,
                writer: Mutex::new(writer),
                socket: stream,
                processor: Mutex::new(processor)
            }
        }

        fn create_reader(&self) -> OfpMessageReader {
            OfpMessageReader::new(self.socket.try_clone().unwrap())
        }
    }

    struct DeviceFuture {
        device: Arc<Device>,
        reader: OfpMessageReader,
    }

    impl DeviceFuture {
        fn new(device: Arc<Device>) -> DeviceFuture {
            DeviceFuture {
                reader: device.create_reader(),
                device,
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
                match self.reader.poll().unwrap() {
                    Async::Ready(Some((header, message))) => {
                        self.device.process_message(header.xid(), message);
                    },
                    _ => {
                        break;
                    }
                }
            }
            Ok(Async::NotReady)
        }
    }

    #[derive(Debug)]
    struct OfpMessageReader {
        socket: TcpStream,
        rd: BytesMut
    }

    impl OfpMessageReader {
        pub fn new(socket: TcpStream) -> Self {
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
                    self.read_body()?;
                } else {
                    self.read_header()?;
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
            let _n = try_ready!(self.socket.read_buf(&mut self.rd));
            if self.have_full_message() {
                Ok(Async::Ready(()))
            } else {
                Ok(Async::NotReady)
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
            let sock_closed = self.read_message_data()?.is_ready();

            if self.have_full_message() {
                let message = self.parse_message()?;
                Ok(Async::Ready(Some(message)))
            } else if sock_closed {
                Ok(Async::Ready(None))
            } else{
                Ok(Async::NotReady)
            }
        }
    }

    #[derive(Debug)]
    struct OfpMessageWriter {
        socket: TcpStream
    }

    impl OfpMessageWriter {
        fn new(socket: TcpStream) -> OfpMessageWriter {
            OfpMessageWriter {
                socket
            }
        }

        fn send_message(&mut self, xid: u32, message: Message) {
            let raw_msg = Message::marshal(xid, message);
            self.socket.write_all(&raw_msg).unwrap()
        }
    }

    #[derive(Debug, Clone, Hash, Eq, PartialEq)]
    pub struct DeviceId(u64);

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
    }

    trait DeviceControllerApp {
        fn event(&self, event: Arc<DeviceControllerEvent>);
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

        fn post(&self, event: DeviceControllerEvent) {
            let event = Arc::new(event);

            for app in &self.apps {
                // TODO Revisit this. Should we call it on a loop or spawn tasks?
                app.event(event.clone());
            }
        }
    }

    pub struct DeviceController {
        devices: Mutex<Devices>,
        message_rx: Mutex<Receiver<(DeviceId, Message)>>,
        message_tx: Sender<(DeviceId, Message)>,

        apps: DeviceControllerApps
    }

    const MESSAGES_CHANNEL_BUFFER: usize = 1000;
    impl DeviceController {
        pub fn new() -> DeviceController {
            let (tx, rx) = mpsc::channel(MESSAGES_CHANNEL_BUFFER);
            DeviceController {
                devices: Mutex::new(Devices::new()),
                message_rx: Mutex::new(rx),
                message_tx: tx,
                apps: DeviceControllerApps::new()
            }
        }

        fn create_device(&self, stream: TcpStream) -> Arc<Device> {
            let mut devices = self.devices.lock().unwrap();
            let device = Arc::new(Device::new(stream, self.message_tx.clone()));
            devices.add_device(device.clone());
            device
        }

        pub fn register_device(&self, stream: TcpStream) {
            let device = self.create_device(stream);
            self.start_reading_messages(device);
        }

        fn start_reading_messages(&self, device: Arc<Device>) {
            tokio::spawn(DeviceFuture::new(device));
        }

        fn post(&self, event: DeviceControllerEvent) {
            self.apps.post(event);
        }
    }

    enum DeviceControllerEvent {
        SwitchConnected(DeviceId),
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

        fn handle_message(&self, device_id: DeviceId, message: Message) {
            match message {
                Message::FeaturesReply(_feats) => {
                    self.controller.post(DeviceControllerEvent::SwitchConnected(device_id));
                },
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
                match rx.poll().unwrap() {
                    Async::Ready(Some((device_id, message))) => {
                        self.handle_message(device_id, message);
                    },
                    _ => {
                        break;
                    }
                }
            }
            Ok(Async::NotReady)
        }
    }
}
