#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut bytes = [0; 1024];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    for _ in 0..8 {
        if rt::write_all(1, &bytes).is_err() {
            return 1;
        }
    }
    0
}
