#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let end = rt::clock().unwrap() + 50_000_000;
    while rt::clock().unwrap() < end {
        for _ in 0..100_000 {
            // Force actual user instructions between clock reads; spin_loop
            // may compile to no instruction for this minimal ISA target.
            unsafe {
                core::arch::asm!("nop", options(nomem, nostack));
            }
        }
    }
    0
}
