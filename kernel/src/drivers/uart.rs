use crate::arch;
use core::fmt::{self, Write};
#[cfg(feature = "instrumented")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};
static BASE: AtomicUsize = AtomicUsize::new(0x10000000);
struct Ring {
    bytes: [u8; 4096],
    head: usize,
    len: usize,
}
impl Ring {
    const fn new() -> Self {
        Self {
            bytes: [0; 4096],
            head: 0,
            len: 0,
        }
    }
    fn push(&mut self, b: u8) -> bool {
        if self.len == 4096 {
            return false;
        }
        self.bytes[(self.head + self.len) % 4096] = b;
        self.len += 1;
        true
    }
    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let b = self.bytes[self.head];
        self.head = (self.head + 1) % 4096;
        self.len -= 1;
        Some(b)
    }
}
static mut RX: Ring = Ring::new();
static mut TX: Ring = Ring::new();
static mut LOST: u64 = 0;
fn read(reg: usize) -> u8 {
    // SAFETY: constant byte register offsets fit the validated 16550 aperture;
    // BASE is the boot physical mapping or the rebound supervisor mapping.
    unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) + reg) as *const u8) }
}
fn write(reg: usize, b: u8) {
    // SAFETY: byte-aligned constant offsets are within the validated UART;
    // volatile access represents MMIO and creates no Rust reference.
    unsafe {
        core::ptr::write_volatile((BASE.load(Ordering::Relaxed) + reg) as *mut u8, b);
    }
}
pub fn init(physical: u64) {
    BASE.store((crate::memory::MMIO + physical) as usize, Ordering::Relaxed);
    write(1, 0);
    write(3, 3);
    write(2, 7);
    write(1, 1);
}
pub fn raw(b: u8) {
    for _ in 0..100_000 {
        if read(5) & 0x20 != 0 {
            write(0, b);
            return;
        }
    }
}

#[cfg(feature = "instrumented")]
static TEST_OUTPUT_FAILED: AtomicBool = AtomicBool::new(false);

/// A failed trusted record permanently prevents later trusted success records.
#[cfg(feature = "instrumented")]
pub fn fail_test_output() {
    TEST_OUTPUT_FAILED.store(true, Ordering::Relaxed);
}

#[cfg(feature = "instrumented")]
pub fn test_counters() -> [u8; 16] {
    let on = arch::disable();
    // SAFETY: the sole UART ISR updates LOST with SIE masked; this scalar copy
    // completes before restoring interrupts and retains no static reference.
    let lost = unsafe { LOST };
    arch::restore(on);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&lost.to_le_bytes());
    bytes[8..]
        .copy_from_slice(&u64::from(TEST_OUTPUT_FAILED.load(Ordering::Relaxed)).to_le_bytes());
    bytes
}

/// Emit one init-only protocol record without the best-effort diagnostic path.
///
/// Called only from the instrumented syscall with SIE enabled. Supervisor-mode
/// timer interrupts do not schedule another process, so the record cannot be
/// interleaved with another user's console write. There is no yield and no long
/// interrupt-masked region. All UART waits share a two-second guest deadline.
#[cfg(feature = "instrumented")]
pub fn test_record(payload: &[u8]) -> Result<(), kernel_abi::Error> {
    use kernel_abi::Error;
    if TEST_OUTPUT_FAILED.load(Ordering::Relaxed) {
        return Err(Error::Io);
    }
    if payload.is_empty() || payload.len() > 512 || !payload.iter().all(|b| (32..=126).contains(b))
    {
        fail_test_output();
        return Err(Error::Invalid);
    }
    let Some(deadline) = crate::frequency()
        .checked_mul(2)
        .and_then(|budget| arch::now().checked_add(budget))
    else {
        fail_test_output();
        return Err(Error::Io);
    };
    // THRE alone permits a byte still waiting in the transmit shift register.
    // TEMT also covers that byte, including QEMU's retry on host backpressure.
    fn ready(mask: u8, deadline: u64) -> Result<(), Error> {
        while read(5) & mask != mask {
            if arch::now() >= deadline {
                return Err(Error::Io);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }
    let result = (|| {
        ready(0x60, deadline)?;
        for bytes in [b"KTEST ".as_slice(), payload, b"\r\n".as_slice()] {
            for byte in bytes {
                ready(0x20, deadline)?;
                write(0, *byte);
            }
        }
        // The newline is the framing commit; do not return before it leaves UART.
        ready(0x60, deadline)
    })();
    if result.is_err() {
        fail_test_output();
    }
    result
}
struct Console;
impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                raw(b'\r');
            }
            raw(b);
        }
        Ok(())
    }
}
pub fn print(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}
pub fn service() {
    let on = arch::disable();
    // SAFETY: interrupt mask serializes both rings with the ISR on the only hart.
    unsafe {
        for _ in 0..64 {
            if read(5) & 1 == 0 {
                break;
            }
            let b = read(0);
            if !(&mut *(&raw mut RX)).push(b) {
                LOST = LOST.saturating_add(1);
            }
        }
        for _ in 0..64 {
            if read(5) & 0x20 == 0 {
                break;
            }
            if let Some(b) = (&mut *(&raw mut TX)).pop() {
                write(0, b);
            } else {
                break;
            }
        }
        write(1, if TX.len > 0 { 3 } else { 1 });
    }
    arch::restore(on);
}
pub fn receive(out: &mut [u8]) -> usize {
    let on = arch::disable();
    service();
    let mut n = 0;
    // SAFETY: SIE is masked on the sole hart; RX is borrowed only until restore,
    // out is an owned disjoint slice and n is checked before every write.
    unsafe {
        while n < out.len() {
            match (&mut *(&raw mut RX)).pop() {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
    }
    arch::restore(on);
    n
}
pub fn transmit(data: &[u8]) -> usize {
    let on = arch::disable();
    let mut n = 0;
    // SAFETY: the only hart has SIE masked; TX and the input slice are disjoint,
    // bounded and live, and the mutable ring borrow ends before restore.
    unsafe {
        while n < data.len() && (&mut *(&raw mut TX)).push(data[n]) {
            n += 1;
        }
    }
    service();
    arch::restore(on);
    n
}
pub fn recovery_read() -> Option<u8> {
    if read(5) & 1 != 0 {
        Some(read(0))
    } else {
        None
    }
}

pub fn readable() -> bool {
    // SAFETY: scheduler calls with SIE masked; this aligned scalar is not retained.
    unsafe { RX.len > 0 }
}
pub fn writable() -> bool {
    // SAFETY: scheduler calls with SIE masked; this aligned scalar is not retained.
    unsafe { TX.len < 4096 }
}
