#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let Ok(base) = rt::page_alloc(1) else {
        return 1;
    };
    // SAFETY: this process exclusively owns the successfully allocated page.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0xa7, 4096);
    }
    // Exit deliberately delegates allocation reclamation to the kernel.
    0
}
