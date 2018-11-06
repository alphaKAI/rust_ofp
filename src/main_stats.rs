use std::net::TcpListener;

extern crate rust_ofp;
use rust_ofp::stats_controller::StatsController;
use rust_ofp::ofp_controller::openflow0x01::OF0x01Controller;
use rust_ofp::controller::MultiController;

fn main() {
    let listener = TcpListener::bind(("127.0.0.1", 6633)).unwrap();
    let multi_controller = MultiController::new();
    for stream in listener.incoming() {
        println!("{:?}", stream);
        match stream {
            Ok(stream) => {
                multi_controller.accept(stream);
            }
            Err(_) => {
                // connection failed
                panic!("Connection failed")
            }
        }
    }
}
