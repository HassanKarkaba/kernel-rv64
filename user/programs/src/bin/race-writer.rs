#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    if rt::write_all(1, &[0x5a]).is_ok() {
        0
    } else {
        1
    }
}
