use std::net::TcpStream;
use rust_ofp::ofp_message::OfpMessage;

/// OpenFlow Controller
///
/// Version-agnostic API for implementing an OpenFlow controller.
pub trait OfpController {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the node associated with the given `TcpStream`.
    fn send_message(xid: u32, message: Self::Message, stream: &mut TcpStream);
    /// Perform handshake and begin loop reading incoming messages from client stream.
    fn handle_client_connected(stream: &mut TcpStream);
}

pub mod openflow0x01 {
    use std::net::TcpStream;

    use rust_ofp::ofp_device::openflow0x01::Device;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct DeviceController {
        devices: Mutex<Vec<Device>>
    }

    impl DeviceController {
        pub fn new() -> DeviceController {
            DeviceController {
                devices: Mutex::new(Vec::new())
            }
        }

        pub fn handle_client_connected(&self, stream: TcpStream) {
            let device = Device::new(stream);
            let mut devices = self.devices.lock().expect("Unlocking devices failed");
            device.start_reading_thread();
            devices.push(device);
        }
    }
}
