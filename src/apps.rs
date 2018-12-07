use std::collections::HashMap;

use tokio::prelude::*;
use tokio::timer::Interval;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ofp_device::openflow0x01::{DeviceControllerApp, DeviceControllerEvent, DeviceId };
use ofp_device::OfpDevice;
use openflow0x01::message::Message;
use openflow0x01::{ StatsReq, StatsReqType, StatsReqBody, OfpPort, PortStats };
use ofp_device::openflow0x01::DeviceController;

fn request_stats(controller: Arc<DeviceController>) {
    controller.list_all_devices().iter().for_each(
        |device| {
            let msg = Message::StatsRequest( StatsReq {
                req_type: StatsReqType::Port,
                flags: 0,
                body: StatsReqBody::PortBody {
                    port_no: OfpPort::OFPPNone as u16
                }
            });

            info!("Requesting port stats for {}", device);
            controller.send_message(device, 0, msg);
        });
}

/// Periodically send stats requests to the device.
pub struct StatsProbing {
    controller: Arc<DeviceController>
}

impl StatsProbing {
    pub fn new(controller: Arc<DeviceController>) -> StatsProbing {
        StatsProbing { controller }
    }

    fn print_port_stats(&self, device_id: &DeviceId, port_stats: &Vec<PortStats>) {
        for port in port_stats {
            self.print_single_port_stats(device_id, port);
        }
    }

    fn print_single_port_stats(&self, device_id: &DeviceId, port_stats: &PortStats) {
        println!("Port stats: {}:{}", device_id, port_stats.port_no);
        println!("tx:{} tx_packets:{} tx_errors:{} tx_dropped:{}",
            port_stats.bytes.tx, port_stats.packets.tx, port_stats.errors.tx, port_stats.dropped.tx);
        println!("rx:{} rx_packets:{} rx_errors:{} rx_dropped:{}",
                 port_stats.bytes.rx, port_stats.packets.rx, port_stats.errors.rx, port_stats.dropped.rx);
    }
}

impl DeviceControllerApp for StatsProbing {
    fn event(&mut self, event: Arc<DeviceControllerEvent>) {
        match *event {
            DeviceControllerEvent::PortStats(ref device_id, ref port_stats) => {
                info!("PORT STATS: {}", port_stats.len());
                self.print_port_stats(device_id, port_stats);
            }
            _ => {}
        }
    }

    fn start(&mut self) {
        info!("Starting app");
        let controller = self.controller.clone();
        let task = Interval::new(Instant::now(), Duration::from_secs(10))
            .for_each(move |instant| {
                info!("Requesting stats");
                request_stats(controller.clone());
                Ok(())
            })
            .map_err(|e| panic!("interval errored; err={:?}", e));
        tokio::spawn(task);
    }
}
