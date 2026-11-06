#![no_std]
#![no_main]
user_runtime::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    // SAFETY: intentional hostile U-mode access. The test requires process termination.
    unsafe {
        core::arch::asm!("ld zero, 0(zero)", options(nostack));
    }
    99
}
