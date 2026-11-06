#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(args: &[&[u8]]) -> i32 {
    if args.len() != 1 || rt::shutdown() != Err(-1) {
        return 1;
    }
    if rt::write(1, b"S") != Ok(1) {
        return 2;
    }
    let mut gate = [0];
    if rt::read(0, &mut gate) != Ok(1) {
        return 3;
    }
    if args[0] == b"peer" {
        let mut value = 7u64;
        for i in 0..100_000 {
            value = value.wrapping_mul(6364136223846793005).wrapping_add(i);
            core::hint::black_box(value);
        }
        if rt::write(1, b"P") != Ok(1) {
            return 4;
        }
        loop {
            value = value.wrapping_mul(2862933555777941757).wrapping_add(1);
            core::hint::black_box(value);
        }
    }
    if rt::write(1, b"R") != Ok(1) {
        return 5;
    }
    let byte = if args[0] == b"writer" { b"A" } else { b"W" };
    if rt::write(2, byte) != Ok(1) {
        return 6;
    }
    // No new userspace syscall should be admitted after the shutdown flag.
    let _ = rt::write(1, b"D");
    0
}
