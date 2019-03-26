use std::io::Cursor;
use std::io::BufRead;
use bytes::Buf;
use byteorder::{ ReadBytesExt, WriteBytesExt};

macro_rules! create_empty_wrapper {
    ($wrapped_name:ident, $wrapper_name:ident) => {
        struct $wrapper_name {
        }
    }
}

pub fn write_padding_bytes(bytes: &mut Vec<u8>, count: usize) {
    for _ in 0..count {
        bytes.write_u8(0).unwrap();
    }
}

// TODO perhaps there is a faster way to do this?
pub fn read_fixed_size_string(bytes: &mut Cursor<Vec<u8>>, max_capacity: usize) -> String {
    let mut arr = Vec::with_capacity(max_capacity);
    let mut read_count: usize = 0;

    // TODO make this return a Result
    assert!(bytes.remaining() >= max_capacity);
    for _i in 0..max_capacity {
        read_count += 1;
        let next_char = bytes.read_u8().unwrap();
        if next_char == 0 {
            break;
        }
        arr.push(next_char);
    }

    bytes.consume(max_capacity - read_count);

    String::from_utf8(arr).unwrap()
}