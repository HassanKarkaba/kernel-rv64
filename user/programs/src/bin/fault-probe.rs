#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(args: &[&[u8]]) -> i32 {
    let mode = args.first().copied().unwrap_or(b"null");
    match mode {
        b"text" => unsafe { core::ptr::write_volatile(0x10000 as *mut u8, 0) },
        b"kernel" => unsafe {
            core::ptr::read_volatile(0x80200000 as *const u8);
        },
        b"guard" => unsafe {
            core::ptr::read_volatile(0x3ffef000 as *const u8);
        },
        b"csr" => unsafe {
            core::arch::asm!("csrr t0, sstatus",out("t0")_);
        },
        b"sfence" => unsafe {
            core::arch::asm!("sfence.vma zero, zero");
        },
        b"execute" => {
            let base = match rt::page_alloc(1) {
                Ok(p) => p,
                Err(_) => return 2,
            };
            // This deliberate execution from an NX anonymous page must fault.
            unsafe {
                core::ptr::write_volatile(base as *mut u32, 0x00008067);
                core::arch::asm!("fence.i");
                let target: extern "C" fn() = core::mem::transmute(base as usize);
                target();
            }
        }
        b"freed" => {
            let base = match rt::page_alloc(1) {
                Ok(p) => p,
                Err(_) => return 2,
            };
            unsafe {
                core::ptr::write_volatile(base as *mut u64, 77);
                core::ptr::read_volatile(base as *const u64);
                if rt::page_free(base, 1).is_err() {
                    return 2;
                }
                core::ptr::read_volatile(base as *const u64);
            }
        }
        b"private" => {
            let p = match rt::page_alloc(1) {
                Ok(p) => p,
                Err(_) => return 2,
            };
            unsafe {
                if core::ptr::read_volatile(p as *const u64) != 0 {
                    return 3;
                }
                core::ptr::write_volatile(p as *mut u64, 0xbb);
            }
            return 0;
        }
        b"sleep" => {
            return if rt::sleep(20).is_ok() { 0 } else { 2 };
        }
        b"exit" => return 0,
        b"badsp" => {
            // All accesses stay in registers while sp/gp are deliberately invalid.
            // ecall must switch to the owned kernel stack and preserve t4/t5/t6.
            let answer: i64;
            unsafe {
                core::arch::asm!("mv t6, sp","mv t5, gp","li sp, 0","li gp, 1234","li t4, 5678","ecall",
                "bne t4, t3, 1f","mv sp, t6","mv gp, t5","j 2f","1: unimp","2:",
                in("t3")5678u64,in("a7")2u64,inlateout("a0")0i64=>answer,
                in("a1")0u64,in("a2")0u64,in("a3")0u64,in("a4")0u64,in("a5")0u64,
                out("t4")_,out("t5")_,out("t6")_);
            }
            return if answer > 0 { 0 } else { 4 };
        }
        _ => unsafe {
            core::arch::asm!("ld t0, 0(zero)",out("t0")_);
        },
    }
    99
}
