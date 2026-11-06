#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
// Explicit raw borrows delimit unsafe global access; direct static references are forbidden in Rust2024.
#![allow(clippy::deref_addrof)]
mod arch;
mod diagnostics;
mod drivers;
mod interleave;
mod memory;
mod metrics;
mod process;
mod syscall;
mod trace;
use core::panic::PanicInfo;
use kernel_platform::dtb::{self, Region};
#[repr(C, align(4096))]
struct BootStack([u8; 524288]);
#[unsafe(no_mangle)]
static mut BOOT_STACK: BootStack = BootStack([0; 524288]);
static mut TIMEBASE: u64 = 0;
macro_rules! log {($($arg:tt)*)=>{crate::drivers::uart::print(format_args!($($arg)*))};}
pub(crate) use log;
pub fn frequency() -> u64 {
    // SAFETY: boot initializes this aligned scalar before scheduler/ISR entry;
    // no code modifies it after publication.
    unsafe { TIMEBASE }
}
pub fn fatal(reason: &str) -> ! {
    arch::disable();
    diagnostics::event("kernel", reason, 0, 0);
    log!("BOOT_FAILED phase=kernel reason={}\n", reason);
    arch::shutdown();
}
#[unsafe(no_mangle)]
extern "C" fn supervisor_fault_emergency() -> ! {
    #[cfg(feature = "instrumented")]
    {
        let cause: u64;
        let pc: u64;
        let value: u64;
        // SAFETY: fatal S-mode entry owns the emergency stack, interrupts remain
        // disabled, and these read-only fault CSRs refer to the interrupted trap.
        unsafe {
            core::arch::asm!("csrr {cause}, scause", "csrr {pc}, sepc", "csrr {value}, stval",
                cause=out(reg)cause, pc=out(reg)pc, value=out(reg)value, options(nostack));
        }
        log!(
            "KFAULT instrumented=1 cause={} pc={:#x} value={:#x}\n",
            cause,
            pc,
            value
        );
    }
    fatal("SUPERVISOR_TRAP")
}
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fatal("KERNEL_PANIC")
}
#[unsafe(no_mangle)]
extern "C" fn kernel_main(hart: u64, dtb_address: u64) -> ! {
    diagnostics::init();
    diagnostics::event("boot", "ENTRY", 0, 0);
    log!("KERNEL-RV64 boot\n");
    if hart != 0 || dtb_address & 7 != 0 || !(0x80000000..0x90000000 - 40).contains(&dtb_address) {
        fatal("BOOT_ARGUMENTS");
    }
    // SAFETY: OpenSBI is a trusted prerequisite; physical window checked before slicing.
    let header = unsafe { core::slice::from_raw_parts(dtb_address as *const u8, 40) };
    let size = dtb::total_size(header).unwrap_or_else(|_| fatal("DTB_HEADER"));
    if dtb_address
        .checked_add(size as u64)
        .is_none_or(|end| end > 0x90000000)
    {
        fatal("DTB_RANGE");
    }
    // SAFETY: the preceding checked end bounds the entire trusted OpenSBI DTB
    // inside RAM; the immutable bytes remain reserved throughout platform parsing.
    let blob = unsafe { core::slice::from_raw_parts(dtb_address as *const u8, size) };
    let platform = dtb::parse(blob).unwrap_or_else(|_| fatal("DTB_PLATFORM"));
    if !arch::probe() {
        fatal("SBI_CAPABILITIES");
    }
    let version = arch::sbi(0x10, 2, [0; 3]);
    log!(
        "SBI implementation_version={} timebase={}\n",
        version.value,
        platform.timebase
    );
    // SAFETY: boot is the unique writer before interrupt admission; all later
    // accesses read this initialized scalar without retaining references.
    unsafe {
        TIMEBASE = platform.timebase;
    }
    diagnostics::event("boot", "PLATFORM_VALIDATED", 0, 0);
    memory::init(
        &platform,
        Region {
            base: dtb_address,
            size: size as u64,
        },
    )
    .unwrap_or_else(|_| fatal("MEMORY_INIT"));
    drivers::uart::init(platform.uart.region.base);
    arch::init_traps();
    drivers::plic::init(&platform);
    arch::interrupt_sources();
    if !arch::timer(arch::now() + platform.timebase / 1000) {
        fatal("SBI_TIMER");
    }
    arch::enable();
    let device = drivers::virtio::Device::negotiate(&platform)
        .unwrap_or_else(|_| recovery("VIRTIO_NEGOTIATION"));
    diagnostics::event("boot", "DEVICE_READY", 0, 0);
    syscall::mount(device).unwrap_or_else(|_| recovery("FILESYSTEM_MOUNT"));
    diagnostics::event("boot", "MOUNT_VALIDATED", 0, 0);
    process::init().unwrap_or_else(|_| fatal("INIT_ELF"));
    log!("READY\n");
    // SAFETY: slot 64 is a mapped aligned supervisor stack with its own guard;
    // this diverging assembly transition retains no boot-stack Rust borrow.
    unsafe { arch::enter_scheduler(memory::stack_top(64)) }
}
pub fn recovery(reason: &str) -> ! {
    arch::disable();
    diagnostics::event("kernel", reason, 0, 0);
    log!(
        "BOOT_FAILED phase=mount reason={}\nRecovery console: status help shutdown\n",
        reason
    );
    let mut line = [0u8; 32];
    let mut n = 0;
    loop {
        if let Some(b) = drivers::uart::recovery_read() {
            if b == b'\r' || b == b'\n' {
                log!("\n");
                match &line[..n] {
                    b"shutdown" => arch::shutdown(),
                    b"status" => log!("FAILED recovery required\n"),
                    _ => log!("status help shutdown\n"),
                };
                n = 0;
            } else if n < line.len() {
                line[n] = b;
                n += 1;
                drivers::uart::raw(b);
            }
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn rust_trap(frame: &mut arch::Trap) {
    if frame.status & 32 != 0 {
        metrics::irq_off(file!(), line!());
    }
    let from_user = frame.status & 256 == 0;
    if from_user {
        metrics::user_exit(process::pid().raw());
    }
    if frame.cause >> 63 != 0 {
        match frame.cause & !(1u64 << 63) {
            5 => {
                interleave::timer(from_user);
                process::watchdog();
                if !arch::timer(arch::now() + frequency() / 1000) {
                    fatal("TIMER_FAILURE");
                }
            }
            9 => drivers::plic::interrupt(),
            _ => fatal("UNEXPECTED_INTERRUPT"),
        }
    } else if from_user {
        if frame.cause == 8 {
            frame.pc = frame.pc.checked_add(4).unwrap_or_else(|| fatal("USER_PC"));
            arch::enable();
            frame.x[10] = syscall::dispatch(frame) as u64;
            arch::disable();
        } else {
            process::exit(kernel_abi::ExitRecord::fault(
                process::pid().raw(),
                frame.cause,
                frame.value,
            ));
        }
    } else {
        fatal("SUPERVISOR_TRAP");
    }
    if from_user {
        process::user_return();
        frame.status = 32;
        metrics::user_enter(process::pid().raw());
    }
    if frame.status & 32 != 0 {
        metrics::irq_on();
    }
}
