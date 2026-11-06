#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut byte = [0u8; 1];
    if rt::read(0, &mut byte) != Ok(1) {
        return 1;
    }
    0
}
