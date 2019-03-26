
use tokio::io;
use tokio::net::TcpStream;
use tokio::prelude::*;

use futures::sync::mpsc;
use futures::sync::mpsc::{Receiver, Sender};

use std::fmt;
use std::sync::Mutex;
use std::sync::Arc;

use rust_ofp::ofp_message::{ OfpMessage, OfpParsingError };
use ofp_header::{OfpHeader, Xid};
use ofp_serialization;

use bytes::BytesMut;

use rust_ofp::message::Message;
use tokio::io::{ ReadHalf, WriteHalf };

use rust_ofp::message::{ PacketIn, StatsResp, StatsRespBody, PortStats, FlowStats, TableStats, QueueStats };
use ofp_header::OPENFLOW_0_01_VERSION;

const WRITING_CHANNEL_SIZE: usize = 1000;

enum OpenFlowVersion {
    Unknown,
    Known(u8)
}

/// Selects the highest OF version that is supported by the device and this lib.
fn select_openflow_version(_device_version: u8) -> u8 {
    OPENFLOW_0_01_VERSION
}

/// OpenFlow Device
///
/// Version-agnostic API for communicating with an OpenFlow Device.
pub trait OfpDevice {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the device.
    fn send_message(&self, xid: u32, message: Self::Message);

    /// Handle a message from the device
    fn process_message(&self, header: OfpHeader, message: Self::Message);
}


#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DeviceId(u64);

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DeviceId({})", self.0)
    }
}

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

pub enum DeviceEvent {
    SwitchConnected(DeviceId),
    PortStats(DeviceId, Vec<PortStats>),
    FlowStats(DeviceId, Vec<FlowStats>),
    TableStats(DeviceId, Vec<TableStats>),
    QueueStats(DeviceId, Vec<QueueStats>),
    AggregateStats(DeviceId, u64, u64, u32),
    PacketIn(DeviceId, PacketIn)
}

struct MessageProcessor {
    state: Arc<Mutex<DeviceState>>,
    tx: Sender<DeviceEvent>,
    writer: Sender<(u8, Xid, Message)>,
    version: OpenFlowVersion
}

impl MessageProcessor {
    fn new(state: Arc<Mutex<DeviceState>>,
           tx: Sender<DeviceEvent>,
           writer: Sender<(u8, Xid, Message)>) -> MessageProcessor {
        MessageProcessor {
            state,
            tx,
            writer,
            version: OpenFlowVersion::Unknown
        }
    }

    fn send_message(&mut self, xid: Xid, message: Message) {
        let version = match self.version {
            OpenFlowVersion::Unknown => {
                OPENFLOW_0_01_VERSION
            },
            OpenFlowVersion::Known(version) => version
        };
        self.writer.try_send((version, xid, message)).unwrap();
    }

    fn process_message(&mut self, header: OfpHeader, message: Message) {
        let mut send_to_controller = None;

        match message {
            Message::Hello => {
                let version = select_openflow_version(header.version());
                info!("Received Hello message with OF version {}, using version {}",
                      header.version(), version);

                self.version = OpenFlowVersion::Known(version);

                self.send_message(header.xid(), Message::FeaturesReq);
            },
            Message::Error(err) => println!("Error: {:?}", err),
            Message::EchoRequest(ref bytes) => {
                self.send_message(header.xid(), Message::EchoReply(bytes.clone()))
            }
            Message::EchoReply(_) => (),
            Message::FeaturesReq => (),
            Message::FeaturesReply(feats) => {
                let mut state = self.state.lock().unwrap();
                if state.switch_id.is_some() {
                    panic!("Switch connection already received.")
                }

                let switch_id = DeviceId(feats.datapath_id);
                state.switch_id = Some(switch_id.clone());
                send_to_controller = Some(DeviceEvent::SwitchConnected(switch_id));
            },
            Message::PacketIn(pkt) => {
                let mut state = self.state.lock().unwrap();
                let device_id = state.get_device_id().unwrap();
                send_to_controller = Some(DeviceEvent::PacketIn(device_id, pkt));
            },
            Message::StatsReply(stats) => {
                let mut state = self.state.lock().unwrap();
                let device_id = state.get_device_id().unwrap();
                send_to_controller = self.handle_stats(device_id, stats);
            },
            Message::FlowMod(_) |
            Message::FlowRemoved(_) |
            Message::PortStatus(_) |
            Message::PacketOut(_) |
            Message::BarrierRequest |
            Message::BarrierReply |
            Message::StatsRequest(_) => (),
        }

        match send_to_controller {
            Some(event) => {
                self.tx.try_send(event).unwrap();
            },
            None => {}
        }
    }

    fn handle_stats(&self, device_id: DeviceId, stats: StatsResp) -> Option<DeviceEvent> {
        match stats.body {
            StatsRespBody::DescBody{ .. } => {
                None
            },
            StatsRespBody::PortBody{ port_stats } => {
                Some(DeviceEvent::PortStats(device_id, port_stats))
            },
            StatsRespBody::TableBody{ table_stats } => {
                Some(DeviceEvent::TableStats(device_id, table_stats))
            },
            StatsRespBody::AggregateStatsBody{ packet_count, byte_count, flow_count } => {
                // TODO improve this. Need to track the request to make the response make
                // sense.
                Some(DeviceEvent::AggregateStats(device_id, packet_count, byte_count, flow_count))
            },
            StatsRespBody::FlowStatsBody{ flow_stats } => {
                Some(DeviceEvent::FlowStats(device_id, flow_stats))
            },
            StatsRespBody::QueueBody{ queue_stats } => {
                Some(DeviceEvent::QueueStats(device_id, queue_stats))
            },
            StatsRespBody::VendorBody => {
                None
            },
        }
    }
}

pub struct Device {
    state: Arc<Mutex<DeviceState>>,
    openflow_version: OpenFlowVersion,

    // TODO this mutex means a lock for every received message
    processor: Arc<Mutex<MessageProcessor>>,

    // TODO this mutex means a lock for every writen message
    writer: Mutex<Sender<(u8, Xid, Message)>>,
}

impl Device {
    pub fn new(stream: TcpStream, tx: Sender<DeviceEvent>) -> Device {
        let (read, write) = stream.split();

        let (writer_tx, writer_rx) = mpsc::channel(WRITING_CHANNEL_SIZE);
        let writer = OfpMessageWriter::new(write, writer_rx);
        let state = Arc::new(Mutex::new(DeviceState::new()));
        let processor = Arc::new(
            Mutex::new(
                MessageProcessor::new(state.clone(), tx, writer_tx.clone())
            )
        );

        let reader = OfpMessageReader::new(read);
        tokio::spawn(writer);
        tokio::spawn(DeviceFuture::new(processor.clone(), reader));

        Device {
            state,
            writer: Mutex::new(writer_tx),
            openflow_version: OpenFlowVersion::Unknown,
            processor
        }
    }

    // TODO this was in the OfpDevice trait. Do we need this trait?
    pub fn send_message(&self, xid: Xid, message: Message) {
        let version = match self.openflow_version {
            OpenFlowVersion::Known(version) => version,
            OpenFlowVersion::Unknown => OPENFLOW_0_01_VERSION,
        };

        let mut writer = self.writer.lock().unwrap();
        writer.try_send((version, xid, message)).unwrap(); // TODO handle errors
    }

    pub fn process_message(&self, header: OfpHeader, message: Message) {
        let mut processor = self.processor.lock().unwrap();
        processor.process_message(header, message);
    }

    pub fn has_device_id(&self, device_id: &DeviceId) -> bool {
        let state = self.state.lock().unwrap();
        state.has_device_id(device_id)
    }

    pub fn get_device_id(&self) -> Option<DeviceId> {
        let state = self.state.lock().unwrap();
        state.get_device_id()
    }

    // TODO wrap this Sender into one that automatically adds the version
    pub fn get_writer(&self) -> Sender<(u8, Xid, Message)> {
        let writer = self.writer.lock().unwrap();
        writer.clone()
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
                    processor.process_message(header, message);
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
    rd: BytesMut,
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

    fn parse_message(&mut self) -> Result<(OfpHeader, Message), OfpParsingError> {
        let body_length = self.get_header_length() - OfpHeader::size();
        let header_data = self.rd.split_to(OfpHeader::size());
        let data = self.rd.split_to(body_length);

        let header = OfpHeader::parse(&header_data);
        let (_xid, body) = ofp_serialization::parse(&header, &data)?;
        Ok((header, body))
    }
}

impl Stream for OfpMessageReader {
    type Item = (OfpHeader, Message);
    type Error = OfpParsingError;

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
    rx: Receiver<(u8, Xid, Message)>,
    message: Option<Vec<u8>>,
}

impl OfpMessageWriter {
    fn new(socket: WriteHalf<TcpStream>, rx: Receiver<(u8, Xid, Message)>) -> OfpMessageWriter {
        OfpMessageWriter {
            socket,
            rx,
            message: None,
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
                Some((version, xid, message)) => {
                    let raw_msg = ofp_serialization::marshal(version, xid, message);
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
