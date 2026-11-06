#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(args: &[&[u8]]) -> i32 {
    if args.is_empty() {
        return 0;
    }
    match args[0] {
        b"exit-max" => unsafe {
            rt::raw(1, [u64::MAX, 0, 0, 0, 0, 0]);
            99
        },
        b"authority" => {
            if rt::shutdown() != Err(-1) {
                return 1;
            }
            if rt::wait(257, true) != Err(-10) {
                return 2;
            }
            0
        }
        b"shared" => {
            if rt::write(1, b"A") != Ok(1) || rt::write(2, b"B") != Ok(1) {
                return 3;
            }
            0
        }
        _ => {
            if args.len() == 16
                && args
                    .iter()
                    .all(|a| a.len() == 63 && a.iter().all(|b| *b == b'x'))
            {
                0
            } else {
                4
            }
        }
    }
}
