#![no_std]

use core::fmt::{self, Write};
pub use kernel_abi as abi;

pub type Result<T> = core::result::Result<T, i64>;

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".section .text.entry",
    ".global _start",
    "_start:",
    ".option push",
    ".option norelax",
    "la gp, __global_pointer$",
    ".option pop",
    "call user_main",
    "unimp",
);

/// # Safety
/// Pointer arguments must uphold the called operation's aliasing and lifetime
/// requirements for the entire syscall, including while the process sleeps.
#[cfg(target_arch = "riscv64")]
pub unsafe fn raw(number: u64, arguments: [u64; 6]) -> i64 {
    let mut result = arguments[0] as i64;
    // SAFETY: caller owns the pointer contract; the ABI preserves all other registers.
    unsafe {
        core::arch::asm!("ecall", in("a7") number, inlateout("a0") result,
        in("a1") arguments[1], in("a2") arguments[2], in("a3") arguments[3],
        in("a4") arguments[4], in("a5") arguments[5], options(nostack));
    }
    result
}

#[cfg(not(target_arch = "riscv64"))]
/// # Safety
/// This host-only implementation always reports ENOSYS and accesses no memory.
pub unsafe fn raw(_number: u64, _arguments: [u64; 6]) -> i64 {
    -38
}

fn result(value: i64) -> Result<u64> {
    if value < 0 {
        Err(value)
    } else {
        Ok(value as u64)
    }
}
fn call(call: abi::Syscall, args: [u64; 6]) -> Result<u64> {
    // SAFETY: this private dispatcher is reached through wrappers with owned slices.
    result(unsafe { raw(call as u64, args) })
}
pub fn exit(code: i32) -> ! {
    let _ = call(abi::Syscall::Exit, [code as u32 as u64, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}
pub fn getpid() -> Result<u64> {
    call(abi::Syscall::GetPid, [0; 6])
}
pub fn yield_now() -> Result<()> {
    call(abi::Syscall::Yield, [0; 6]).map(|_| ())
}
pub fn sleep(ms: u64) -> Result<()> {
    call(abi::Syscall::Sleep, [ms, 0, 0, 0, 0, 0]).map(|_| ())
}
pub fn clock() -> Result<u64> {
    call(abi::Syscall::Clock, [0; 6])
}
pub fn abi_info() -> Result<[u8; 32]> {
    let mut output = [0; 32];
    call(
        abi::Syscall::AbiInfo,
        [output.as_mut_ptr() as u64, 0, 0, 0, 0, 0],
    )?;
    Ok(output)
}
pub fn page_alloc(pages: u64) -> Result<u64> {
    call(abi::Syscall::PageAlloc, [pages, 0, 0, 0, 0, 0])
}
/// # Safety
/// The caller must own the exact allocation and destroy all references into it
/// before freeing it. Neither this function nor the kernel can check Rust aliases.
pub unsafe fn page_free(base: u64, pages: u64) -> Result<()> {
    call(abi::Syscall::PageFree, [base, pages, 0, 0, 0, 0]).map(|_| ())
}
pub fn read(fd: u32, output: &mut [u8]) -> Result<usize> {
    call(
        abi::Syscall::Read,
        [
            fd as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
            0,
            0,
            0,
        ],
    )
    .map(|n| n as usize)
}
pub fn write(fd: u32, input: &[u8]) -> Result<usize> {
    call(
        abi::Syscall::Write,
        [
            fd as u64,
            input.as_ptr() as u64,
            input.len() as u64,
            0,
            0,
            0,
        ],
    )
    .map(|n| n as usize)
}
#[derive(Debug, Clone, Copy)]
pub struct TransferError {
    pub completed: usize,
    pub error: i64,
}
pub fn write_all(fd: u32, input: &[u8]) -> core::result::Result<usize, TransferError> {
    let mut completed = 0;
    while completed < input.len() {
        let end = (completed + abi::MAX_IO).min(input.len());
        match write(fd, &input[completed..end]) {
            Ok(0) => {
                return Err(TransferError {
                    completed,
                    error: -5,
                });
            }
            Ok(n) if n <= end - completed => completed += n,
            Ok(_) => {
                return Err(TransferError {
                    completed,
                    error: -5,
                });
            }
            Err(error) => return Err(TransferError { completed, error }),
        }
    }
    Ok(completed)
}
pub fn open(path: &[u8], flags: u64) -> Result<u32> {
    call(
        abi::Syscall::Open,
        [path.as_ptr() as u64, path.len() as u64, flags, 0, 0, 0],
    )
    .map(|v| v as u32)
}
pub fn close(fd: u32) -> Result<()> {
    call(abi::Syscall::Close, [fd as u64, 0, 0, 0, 0, 0]).map(|_| ())
}
pub fn seek(fd: u32, offset: u64) -> Result<u64> {
    call(abi::Syscall::Seek, [fd as u64, offset, 0, 0, 0, 0])
}
pub fn fsync(fd: u32) -> Result<()> {
    call(abi::Syscall::Fsync, [fd as u64, 0, 0, 0, 0, 0]).map(|_| ())
}
pub fn dup(fd: u32) -> Result<u32> {
    call(abi::Syscall::Dup, [fd as u64, 0, 0, 0, 0, 0]).map(|n| n as u32)
}
pub fn pipe() -> Result<[u32; 2]> {
    let mut out = [0u8; 8];
    call(abi::Syscall::Pipe, [out.as_mut_ptr() as u64, 0, 0, 0, 0, 0])?;
    Ok([
        u32::from_le_bytes(out[..4].try_into().unwrap()),
        u32::from_le_bytes(out[4..].try_into().unwrap()),
    ])
}
pub fn spawn(path: &[u8], args: &[&[u8]], stdio: [i32; 3]) -> Result<u64> {
    if args.len() > 16 {
        return Err(-7);
    }
    let mut argv = [0u8; 256];
    for (i, bytes) in args.iter().enumerate() {
        argv[i * 16..i * 16 + 16].copy_from_slice(
            &abi::ArgSlice {
                pointer: bytes.as_ptr() as u64,
                length: bytes.len() as u64,
            }
            .encode(),
        );
    }
    let mut map = [0; 12];
    for (i, fd) in stdio.iter().enumerate() {
        map[i * 4..i * 4 + 4].copy_from_slice(&fd.to_le_bytes());
    }
    call(
        abi::Syscall::Spawn,
        [
            path.as_ptr() as u64,
            path.len() as u64,
            argv.as_ptr() as u64,
            args.len() as u64,
            map.as_ptr() as u64,
            0,
        ],
    )
}
pub fn wait(pid: u64, nohang: bool) -> Result<abi::ExitRecord> {
    let mut bytes = [0; 32];
    let reaped = call(
        abi::Syscall::Wait,
        [pid, bytes.as_mut_ptr() as u64, nohang as u64, 0, 0, 0],
    )?;
    Ok(abi::ExitRecord {
        pid: reaped,
        kind: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        code: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        cause: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        fault_address: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    })
}
pub fn unlink(path: &[u8]) -> Result<()> {
    call(
        abi::Syscall::Unlink,
        [path.as_ptr() as u64, path.len() as u64, 0, 0, 0, 0],
    )
    .map(|_| ())
}
pub fn rename(old: &[u8], new: &[u8]) -> Result<()> {
    call(
        abi::Syscall::Rename,
        [
            old.as_ptr() as u64,
            old.len() as u64,
            new.as_ptr() as u64,
            new.len() as u64,
            0,
            0,
        ],
    )
    .map(|_| ())
}
pub fn list(records: &mut [[u8; 64]]) -> Result<usize> {
    call(
        abi::Syscall::List,
        [
            records.as_mut_ptr() as u64,
            records.len() as u64,
            0,
            0,
            0,
            0,
        ],
    )
    .map(|n| n as usize)
}
pub fn stat(path: &[u8]) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    call(
        abi::Syscall::Stat,
        [
            path.as_ptr() as u64,
            path.len() as u64,
            output.as_mut_ptr() as u64,
            0,
            0,
            0,
        ],
    )?;
    Ok(output)
}
pub fn process_list(records: &mut [[u8; 32]]) -> Result<usize> {
    call(
        abi::Syscall::ProcessList,
        [
            records.as_mut_ptr() as u64,
            records.len() as u64,
            0,
            0,
            0,
            0,
        ],
    )
    .map(|n| n as usize)
}
pub fn shutdown() -> Result<()> {
    call(abi::Syscall::Shutdown, [0; 6]).map(|_| ())
}

pub struct Console(pub u32);
impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_all(self.0, s.as_bytes())
            .map(|_| ())
            .map_err(|_| fmt::Error)
    }
}
pub fn print(arguments: fmt::Arguments<'_>) {
    let _ = Console(1).write_fmt(arguments);
}
pub fn error(arguments: fmt::Arguments<'_>) {
    let _ = Console(2).write_fmt(arguments);
}

#[macro_export]
macro_rules! print { ($($arg:tt)*) => { $crate::print(core::format_args!($($arg)*)) } }
#[macro_export]
macro_rules! println { () => { $crate::print!("\n") }; ($($arg:tt)*) => { $crate::print(core::format_args!("{}\n", core::format_args!($($arg)*))) } }
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        extern "C" fn user_main(argc: usize, argv: u64) -> ! {
            if $crate::abi_info() != Ok($crate::abi::abi_info()) {
                $crate::exit(126);
            }
            let mut arguments: [&[u8]; 16] = [&[]; 16];
            if argc > 16 {
                $crate::exit(127);
            }
            for (i, arg) in arguments[..argc].iter_mut().enumerate() {
                // SAFETY: the immutable initial stack layout is supplied by the kernel.
                let wire = unsafe { core::ptr::read_unaligned((argv as *const [u8; 16]).add(i)) };
                let slice = $crate::abi::ArgSlice::decode(&wire);
                if slice.length > 255 {
                    $crate::exit(127);
                }
                // SAFETY: kernel-owned initial argument bytes lie in this process's stack.
                *arg = unsafe {
                    core::slice::from_raw_parts(slice.pointer as *const u8, slice.length as usize)
                };
            }
            $crate::exit($main(&arguments[..argc]));
        }
    };
}

#[cfg(target_arch = "riscv64")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = write_all(2, b"program panic\n");
    exit(127)
}
