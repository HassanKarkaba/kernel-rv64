#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut start = [0u8; 1];
    if rt::read(0, &mut start) != Ok(1) {
        return 1;
    }
    let _ = rt::close(0);
    for _ in 0..10_000 {
        if rt::sleep(10).is_err() {
            return 2;
        }
    }
    0
}
