use rust_ofp::ofp_header::OfpHeader;
use rust_ofp::ofp_message::OfpMessage;
use std::io;

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

pub trait OfpMessageReader {
    type Message: OfpMessage;

    fn read_message(&mut self) -> io::Result<Option<(OfpHeader, Self::Message)>>;
}

pub mod openflow0x01 {
    use super::*;
    use std::io::{Write, Read};
    use std::net::TcpStream;

    use rust_ofp::ofp_header::OfpHeader;
    use rust_ofp::ofp_message::OfpMessage;
    use rust_ofp::openflow0x01::message::Message;
    use std::sync::Mutex;
    use std::sync::Arc;

    #[derive(Debug)]
    struct DeviceState {
        switch_id: Option<u64>,
        stream: TcpStream
    }

    impl DeviceState {
        fn new(stream: TcpStream) -> DeviceState {
            DeviceState {
                switch_id: None,
                stream
            }
        }
    }

    impl DeviceState {
        fn send_message(&mut self, xid: u32, message: Message) {
            let raw_msg = Message::marshal(xid, message);
            self.stream.write_all(&raw_msg).unwrap()
        }

        fn process_message(&mut self, xid: u32, message: Message) {
            match message {
                Message::Hello => self.send_message(xid, Message::FeaturesReq),
                Message::Error(err) => println!("Error: {:?}", err),
                Message::EchoRequest(bytes) => {
                    self.send_message(xid, Message::EchoReply(bytes))
                }
                Message::EchoReply(_) => (),
                Message::FeaturesReq => (),
                Message::FeaturesReply(feats) => {
                    if self.switch_id.is_some() {
                        panic!("Switch connection already received.")
                    }

                    self.switch_id = Some(feats.datapath_id);
                    //self.switch_connected(cntl, feats.datapath_id, feats)
                }
                Message::FlowMod(_) => (),
                Message::PacketIn(pkt) => {
                    //self.packet_in(cntl, self.switch_id.unwrap(), xid, pkt)
                }
                Message::FlowRemoved(_) |
                Message::PortStatus(_) |
                Message::PacketOut(_) |
                Message::BarrierRequest |
                Message::BarrierReply => (),
            }
        }
    }

    #[derive(Debug)]
    pub struct Device {
        state: Arc<Mutex<DeviceState>>,
        stream: TcpStream
    }

    impl OfpDevice for Device {
        type Message = Message;

        fn send_message(&self, xid: u32, message: Message) {
            let mut state = self.state.lock().unwrap();
            state.send_message(xid, message)
        }

        fn process_message(&self, xid: u32, message: Message) {
            let mut state = self.state.lock().unwrap();
            state.process_message(xid, message)
        }
    }

    impl Device {
        pub fn new(stream: TcpStream) -> Device {
            Device {
                stream: stream.try_clone().unwrap(),
                state: Arc::new(Mutex::new(DeviceState::new(stream)))
            }
        }

        pub fn start_reading_thread(&self) {
            let mut stream = self.stream.try_clone().expect("Failed to clone TcpStream");
            let state = self.state.clone();
            std::thread::spawn(move || {
                loop {
                    let res = stream.read_message();
                    match res {
                        Ok(message) => {
                            match message {
                                Some((header, body)) => {
                                    let mut state_mut = state.lock().unwrap();
                                    state_mut.process_message(header.xid(), body);
                                },
                                None => {
                                    println!("Connection closed reading header.");
                                    break
                                }
                            }
                        }
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                }
            });
        }
    }

    impl OfpMessageReader for TcpStream {
        type Message = Message;

        fn read_message(&mut self) -> io::Result<Option<(OfpHeader, Self::Message)>> {
            let mut buf = [0u8; 8];

            let res = self.read(&mut buf);
            match res {
                Ok(num_bytes) if num_bytes > 0 => {
                    let header = OfpHeader::parse(buf);
                    let message_len = header.length() - OfpHeader::size();
                    let mut message_buf = vec![0; message_len];
                    let _ = self.read(&mut message_buf);
                    let (_xid, body) = Message::parse(&header, &message_buf);
                    Ok(Some((header, body)))
                }
                Ok(_) => {
                    Ok(None)
                }
                Err(e) => {
                    Err(e)
                }
            }
        }
    }
}
