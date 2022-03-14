#![crate_name = "rust_ofp"]
#![crate_type = "lib"]
#![allow(clippy::unused_io_amount)]
extern crate byteorder;
extern crate tokio;
#[macro_use]
extern crate futures;
extern crate bytes;

#[macro_use]
extern crate log;
extern crate log4rs;

extern crate failure;

#[macro_use]
extern crate failure_derive;

pub mod apps;
pub mod learning_switch;

mod bits;

#[macro_use]
mod ofp_utils;

pub mod message;
pub mod ofp_controller;
pub mod ofp_device;
pub mod ofp_header;
pub mod ofp_message;
pub mod ofp_serialization;
pub mod openflow;
pub mod openflow0x01;
pub mod openflow0x04;
pub mod packet;

mod rust_ofp {
    pub use super::*;
}
