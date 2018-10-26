use std::net::TcpListener;

extern crate rust_ofp;
use rust_ofp::stats_controller::StatsController;

fn main() {
    let listener = TcpListener::bind(("127.0.0.1", 6633)).unwrap();
    for stream in listener.incoming() {
        println!("{:?}", stream);
        match stream {
            Ok(stream) => {
                let mut controller = StatsController::new(stream);
                controller.start();
            }
            Err(_) => {
                // connection failed
                panic!("Connection failed")
            }
        }
    }
}
