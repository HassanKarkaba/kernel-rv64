//! Bounded complete-record ring. Default records never include user payloads.
use core::fmt::{self, Write};
const CAPACITY: usize = 65536;
struct Buffer {
    bytes: [u8; 512],
    len: usize,
}
impl Write for Buffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
struct Ring {
    bytes: [u8; CAPACITY],
    head: usize,
    len: usize,
    lost: u64,
    sequence: u64,
    boot: u64,
}
impl Ring {
    const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            head: 0,
            len: 0,
            lost: 0,
            sequence: 0,
            boot: 0,
        }
    }
    fn append(&mut self, data: &[u8]) {
        let needed = data.len() + 2;
        while self.len + needed > CAPACITY {
            let size = usize::from(self.bytes[self.head])
                | usize::from(self.bytes[(self.head + 1) % CAPACITY]) << 8;
            self.head = (self.head + size + 2) % CAPACITY;
            self.len -= size + 2;
            self.lost = self.lost.saturating_add(1);
        }
        for b in (data.len() as u16).to_le_bytes().iter().chain(data) {
            self.bytes[(self.head + self.len) % CAPACITY] = *b;
            self.len += 1;
        }
    }
}
static mut RING: Ring = Ring::new();
pub fn init() {
    // SAFETY: earliest single-hart boot runs before any ISR or scheduler uses RING.
    unsafe {
        RING.boot = crate::arch::now();
    }
}
pub fn event(subsystem: &str, code: &str, pid: u64, transaction: u64) {
    let on = crate::arch::disable();
    let mut buffer = Buffer {
        bytes: [0; 512],
        len: 0,
    };
    // SAFETY: no scheduling occurs while RING is borrowed; the sole hart has its
    // interrupts masked. Formatter contains only kernel-selected labels/numbers.
    unsafe {
        let ring = &mut *(&raw mut RING);
        ring.sequence = ring.sequence.saturating_add(1);
        let formatted = writeln!(
            &mut buffer,
            "KLOG {{\"schema\":1,\"boot_id\":{},\"timestamp\":{},\"subsystem\":\"{}\",\"event\":\"{}\",\"pid\":{},\"transaction\":{},\"sequence\":{},\"lost\":{}}}",
            ring.boot,
            crate::arch::now(),
            subsystem,
            code,
            pid,
            transaction,
            ring.sequence,
            ring.lost
        );
        if formatted.is_ok() {
            ring.append(&buffer.bytes[..buffer.len]);
        } else {
            ring.lost = ring.lost.saturating_add(1);
            buffer.len = 0;
        }
    }
    crate::arch::restore(on);
    for b in &buffer.bytes[..buffer.len] {
        crate::drivers::uart::raw(*b);
    }
}
