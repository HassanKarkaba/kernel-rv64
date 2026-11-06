//! Hardware boundaries. Only this module may directly change supervisor CSRs.
use core::arch::{asm, global_asm};
global_asm!(include_str!("riscv/entry.S"));
global_asm!(include_str!("riscv/trap.S"));
#[repr(C, align(16))]
pub struct Trap {
    pub x: [u64; 32],
    pub pc: u64,
    pub status: u64,
    pub cause: u64,
    pub value: u64,
}
impl Trap {
    pub const ZERO: Self = Self {
        x: [0; 32],
        pc: 0,
        status: 32,
        cause: 0,
        value: 0,
    };
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context(pub [u64; 14]);
impl Context {
    pub const ZERO: Self = Self([0; 14]);
}
unsafe extern "C" {
    pub fn switch_context(old: *mut Context, new: *const Context);
    pub fn enter_user(frame: *mut Trap) -> !;
    pub fn enter_scheduler(stack: u64) -> !;
    fn trap_entry();
}
#[derive(Clone, Copy)]
pub struct Sbi {
    pub error: i64,
    pub value: u64,
}
pub fn sbi(ext: u64, function: u64, args: [u64; 3]) -> Sbi {
    let mut a0 = args[0];
    let mut a1 = args[1];
    // SAFETY: the trusted SBI ABI permits these registers. No Rust memory is passed.
    unsafe {
        asm!("ecall",inlateout("a0")a0,inlateout("a1")a1,in("a2")args[2],in("a6")function,in("a7")ext,options(nostack));
    }
    Sbi {
        error: a0 as i64,
        value: a1,
    }
}
pub fn probe() -> bool {
    sbi(0x10, 0, [0; 3]).error == 0
        && [0x54494d45, 0x53525354].iter().all(|e| {
            let r = sbi(0x10, 3, [*e, 0, 0]);
            r.error == 0 && r.value != 0
        })
}
pub fn now() -> u64 {
    let n;
    // SAFETY: S-mode may read time because trusted OpenSBI enables the counter. This
    // register-only access has a compiler memory barrier for ordered measurements.
    unsafe {
        asm!("rdtime {}",out(reg)n,options(nostack));
    }
    n
}
pub fn timer(deadline: u64) -> bool {
    sbi(0x54494d45, 0, [deadline, 0, 0]).error == 0
}
#[track_caller]
pub fn disable() -> bool {
    let old: u64;
    // SAFETY: S-mode owns sstatus on this sole hart. Clearing SIE does not access
    // Rust memory; omitting nomem prevents memory motion across this critical boundary.
    unsafe {
        asm!("csrrci {}, sstatus, 2",out(reg)old,options(nostack));
    }
    let enabled = old & 2 != 0;
    if enabled {
        let caller = core::panic::Location::caller();
        crate::metrics::irq_off(caller.file(), caller.line());
    }
    enabled
}
pub fn enable() {
    crate::metrics::irq_on();
    // SAFETY: Trap vectors and stacks are initialized before enabling interrupts.
    // No exclusive global borrow survives this compiler/hardware interrupt boundary.
    unsafe {
        asm!("csrsi sstatus, 2", options(nostack));
    }
}
pub fn restore(on: bool) {
    if on {
        enable();
    }
}
pub fn wait() {
    // SAFETY: Only kernel idle code uses wfi with a valid supervisor stack and
    // configured interrupt sources. No Rust pointers are consumed or retained.
    unsafe {
        asm!("wfi", options(nostack));
    }
}
pub fn fence() {
    // SAFETY: This S-mode ordering instruction touches no Rust references. Its
    // memory clobber and I/O fence order descriptor publication and DMA observations.
    unsafe {
        asm!("fence iorw, iorw", options(nostack));
    }
}
pub fn translation_fence() {
    // SAFETY: All address spaces use ASID zero on one hart. Full sfence.vma
    // completes invalidation before any unmapped physical frame or table is reused.
    unsafe {
        asm!("sfence.vma zero, zero", options(nostack));
    }
}
pub fn instruction_fence() {
    // SAFETY: The sole hart has finished writing and protecting executable
    // bytes. fence.i synchronizes instruction fetch; no Rust pointer escapes.
    unsafe {
        asm!("fence.i", options(nostack));
    }
}
pub fn activate(root: u64) -> bool {
    let satp = (8u64 << 60) | (root >> 12);
    let actual: u64;
    // SAFETY: Internal callers supply an aligned live TABLE_POOL root with shared
    // supervisor mappings. satp changes and full ASID-zero invalidation stay adjacent.
    unsafe {
        asm!("csrw satp, {s}","sfence.vma zero, zero","csrr {a}, satp",s=in(reg)satp,a=out(reg)actual,options(nostack));
    }
    actual == satp
}
pub fn init_traps() {
    // SAFETY: The linked trap entry is aligned executable kernel text; sscratch
    // starts in supervisor mode. SUM/MXR/FS/VS are cleared before any user execution.
    unsafe {
        asm!("csrw stvec, {v}","csrw sscratch, zero","csrc sstatus, {clear}",v=in(reg)trap_entry as *const () as u64,clear=in(reg)((1u64<<18)|(1u64<<19)|(3u64<<13)|(3u64<<9)),options(nostack));
    }
}
pub fn interrupt_sources() {
    // SAFETY: PLIC and timer handlers/stacks are ready. Only supervisor
    // timer and external sources are enabled; this scalar CSR write retains no alias.
    unsafe {
        asm!("csrw sie, {}",in(reg)((1u64<<5)|(1u64<<9)),options(nostack));
    }
}
pub fn shutdown() -> ! {
    let _ = sbi(0x53525354, 0, [0, 0, 0]);
    disable();
    loop {
        wait();
    }
}
