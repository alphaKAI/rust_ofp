
extern crate tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

extern crate rust_ofp;
use rust_ofp::learning_switch::LearningSwitchApp;
use rust_ofp::ofp_device::openflow0x01::{DeviceController, DeviceControllerFuture};
use std::sync::Arc;


fn process(socket: TcpStream, controller: Arc<DeviceController>) {
    controller.register_device(socket);
}

fn main() {
    let controller = Arc::new(DeviceController::new());
    controller.register_app(Box::new(LearningSwitchApp::new(controller.clone())));

    let addr = "127.0.0.1:6633".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let controller_future = DeviceControllerFuture::new(controller.clone());
    let server = listener.incoming().for_each(move |socket| {
            process(socket, controller.clone());
            Ok(())
        })
        .map_err(|err| {
            println!("accept error = {:?}", err);
        });

    let lazy_future = future::lazy(|| {
        tokio::spawn(controller_future);
        tokio::spawn(server);
        Ok(())
    });

    println!("OF controller running on localhost:6633");
    tokio::run(lazy_future);
}
