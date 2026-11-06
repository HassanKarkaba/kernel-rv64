//! One modern split queue. Buffers remain in static kernel memory through reset.
use super::Mmio;
use crate::{arch, memory};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use disk_format::{Block, BlockDevice, Error, Result};
use kernel_platform::{
    dtb::Platform,
    virtqueue::{Operation, valid_transfer, validate_completion},
};
#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}
const EMPTY: Desc = Desc {
    addr: 0,
    len: 0,
    flags: 0,
    next: 0,
};
#[repr(C, align(4096))]
struct Queue {
    desc: [Desc; 8],
    avail_flags: u16,
    avail_idx: u16,
    avail_ring: [u16; 8],
    used_event: u16,
    padding: [u8; 3946],
    used_flags: u16,
    used_idx: u16,
    used: [Used; 8],
    avail_event: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Used {
    id: u32,
    len: u32,
}
// Used ring starts at 4096, split from the descriptor/available page.
static mut QUEUE: Queue = Queue {
    desc: [EMPTY; 8],
    avail_flags: 0,
    avail_idx: 0,
    avail_ring: [0; 8],
    used_event: 0,
    padding: [0; 3946],
    used_flags: 0,
    used_idx: 0,
    used: [Used { id: 0, len: 0 }; 8],
    avail_event: 0,
};
#[repr(C, align(4096))]
struct Request {
    header: [u8; 16],
    data: [u8; 4096],
    status: u8,
}
static mut REQUEST: Request = Request {
    header: [0; 16],
    data: [0; 4096],
    status: 255,
};
#[cfg(feature = "instrumented")]
static TEST_NEXT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "instrumented")]
static TEST_ACTIVE: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "instrumented")]
pub fn inject_next(mode: u64) -> core::result::Result<(), kernel_abi::Error> {
    if !(1..=7).contains(&mode) {
        return Err(kernel_abi::Error::Invalid);
    }
    TEST_NEXT.store(mode as u32, Ordering::Release);
    Ok(())
}
fn withholding() -> bool {
    #[cfg(feature = "instrumented")]
    {
        TEST_ACTIVE.load(Ordering::Acquire) >= 6
    }
    #[cfg(not(feature = "instrumented"))]
    {
        false
    }
}
static BASE: AtomicU64 = AtomicU64::new(0);
static APERTURE: AtomicU64 = AtomicU64::new(0);
static IRQ: AtomicU32 = AtomicU32::new(0);
pub struct Device {
    base: u64,
    aperture: usize,
    used: u16,
    avail: u16,
    failed: bool,
    frequency: u64,
    serial: u64,
}
impl Device {
    pub fn negotiate(p: &Platform) -> Result<Self> {
        let mut chosen = None;
        for slot in &p.virtio[..p.virtio_count] {
            // SAFETY: DTB-validated aperture is mapped supervisor-only for this device.
            // Constructor retains no Rust reference; each register access checks its bounds.
            let dev =
                unsafe { Mmio::new(memory::MMIO + slot.region.base, slot.region.size as usize) };
            if dev.read(0) == 0x74726976 && dev.read(8) == 2 {
                if chosen.is_some() {
                    return Err(Error::Shape);
                }
                chosen = Some(slot);
            }
        }
        let slot = chosen.ok_or(Error::Io)?;
        let base = memory::MMIO + slot.region.base;
        // SAFETY: DTB-validated aperture is mapped supervisor-only for this device.
        // Constructor retains no Rust reference; each register access checks its bounds.
        let d = unsafe { Mmio::new(base, slot.region.size as usize) };
        if d.read(4) != 2 {
            return Err(Error::Version);
        }
        d.write(0x70, 0);
        if d.read(0x70) != 0 {
            return Err(Error::Io);
        }
        d.write(0x70, 1);
        d.write(0x70, 3);
        d.write(0x14, 0);
        let low = d.read(0x10);
        d.write(0x14, 1);
        let high = d.read(0x10);
        if low & (1 << 9) == 0 || low & (1 << 5) != 0 || high & 1 == 0 {
            d.write(0x70, 128);
            return Err(Error::Version);
        }
        d.write(0x24, 0);
        d.write(0x20, 1 << 9);
        d.write(0x24, 1);
        d.write(0x20, 1);
        d.write(0x70, 11);
        if d.read(0x70) & 8 == 0 {
            return Err(Error::Version);
        }
        d.write(0x30, 0);
        if d.read(0x34) < 8 || d.read(0x44) != 0 {
            return Err(Error::Capacity);
        }
        d.write(0x38, 8);
        let desc = &raw mut QUEUE as u64;
        // SAFETY: The reset device has no DMA ownership yet. QUEUE is aligned static
        // memory with verified field layout; raw field addresses create no Rust references.
        let avail = unsafe { &raw mut QUEUE.avail_flags } as u64;
        let used = unsafe { &raw mut QUEUE.used_flags } as u64;
        for (reg, addr) in [(0x80, desc), (0x90, avail), (0xa0, used)] {
            d.write(reg, addr as u32);
            d.write(reg + 4, (addr >> 32) as u32);
        }
        arch::fence();
        d.write(0x44, 1);
        let mut capacity = None;
        for _ in 0..8 {
            let generation = d.read(0xfc);
            let n = u64::from(d.read(0x100)) | u64::from(d.read(0x104)) << 32;
            if d.read(0xfc) == generation {
                capacity = Some(n);
                break;
            }
        }
        if capacity != Some(131072) {
            d.write(0x70, 128);
            return Err(Error::Size);
        }
        APERTURE.store(slot.region.size, Ordering::Release);
        BASE.store(base, Ordering::Release);
        IRQ.store(slot.irq, Ordering::Release);
        d.write(0x70, 15);
        Ok(Self {
            base,
            aperture: slot.region.size as usize,
            used: 0,
            avail: 0,
            failed: false,
            frequency: p.timebase,
            serial: 0,
        })
    }
    fn perform(&mut self, op: Operation, sector: u64, data: &mut [u8]) -> Result<()> {
        if self.failed || !valid_transfer(op, sector, data.len()) {
            return Err(Error::Io);
        }
        #[cfg(feature = "instrumented")]
        TEST_ACTIVE.store(TEST_NEXT.swap(0, Ordering::AcqRel), Ordering::Release);
        let len = data.len();
        self.serial = self.serial.checked_add(1).ok_or(Error::Io)?;
        let kind = match op {
            Operation::Read => 0u32,
            Operation::Write => 1,
            Operation::Flush => 4,
        };
        // SAFETY: filesystem serialization grants sole queue ownership. No DMA is active.
        unsafe {
            let r = &mut *(&raw mut REQUEST);
            r.header.fill(0);
            r.header[..4].copy_from_slice(&kind.to_le_bytes());
            r.header[8..].copy_from_slice(&sector.to_le_bytes());
            r.status = 255;
            if matches!(op, Operation::Write) {
                r.data[..len].copy_from_slice(data);
            }
            let q = &mut *(&raw mut QUEUE);
            q.desc[0] = Desc {
                addr: r.header.as_ptr() as u64,
                len: 16,
                flags: 1,
                next: if len == 0 { 2 } else { 1 },
            };
            q.desc[1] = Desc {
                addr: r.data.as_mut_ptr() as u64,
                len: len as u32,
                flags: 1 | if matches!(op, Operation::Read) { 2 } else { 0 },
                next: 2,
            };
            q.desc[2] = Desc {
                addr: &raw mut r.status as u64,
                len: 1,
                flags: 2,
                next: 0,
            };
            core::ptr::write_volatile(&raw mut q.avail_ring[self.avail as usize % 8], 0);
        }
        arch::fence();
        self.avail = self.avail.wrapping_add(1);
        // SAFETY: The serialized filesystem owner retains this static queue/request
        // until validated completion or confirmed reset. Aligned volatile fields observe
        // device-owned DMA; publication/completion fences order accesses and no reference
        // to shared DMA memory survives a scheduling point.
        unsafe {
            core::ptr::write_volatile(&raw mut QUEUE.avail_idx, self.avail);
        }
        arch::fence();
        // SAFETY: DTB-validated aperture is mapped supervisor-only for this device.
        // Constructor retains no Rust reference; each register access checks its bounds.
        let d = unsafe { Mmio::new(self.base, self.aperture) };
        let start = arch::now();
        let deadline = start
            .checked_add(self.frequency.checked_mul(5).ok_or(Error::Io)?)
            .ok_or(Error::Io)?;
        d.write(0x50, 0);
        crate::trace::event(7, self.serial, u64::from(kind));
        crate::interleave::before(3);
        crate::interleave::io_before_check();
        loop {
            let observed = if withholding() || crate::interleave::withhold_io() {
                self.used
            } else {
                // SAFETY: The serialized filesystem owner retains this static queue/request
                // until validated completion or confirmed reset. Aligned volatile fields observe
                // device-owned DMA; publication/completion fences order accesses and no reference
                // to shared DMA memory survives a scheduling point.
                unsafe { core::ptr::read_volatile(&raw const QUEUE.used_idx) }
            };
            if observed != self.used {
                arch::fence();
                if observed != self.used.wrapping_add(1) {
                    return self.fail();
                }
                // SAFETY: The serialized filesystem owner retains this static queue/request
                // until validated completion or confirmed reset. Aligned volatile fields observe
                // device-owned DMA; publication/completion fences order accesses and no reference
                // to shared DMA memory survives a scheduling point.
                let used = unsafe {
                    core::ptr::read_volatile(&raw const QUEUE.used[self.used as usize % 8])
                };
                // SAFETY: The serialized filesystem owner retains this static queue/request
                // until validated completion or confirmed reset. Aligned volatile fields observe
                // device-owned DMA; publication/completion fences order accesses and no reference
                // to shared DMA memory survives a scheduling point.
                let status = unsafe { core::ptr::read_volatile(&raw const REQUEST.status) };
                self.used = observed;
                // The instrumented candidate alters only the observed completion;
                // release candidates contain no fault selector or substitution.
                #[cfg(feature = "instrumented")]
                let (used, status) = {
                    let mode = TEST_ACTIVE.load(Ordering::Acquire);
                    match mode {
                        1 => (used, 1),
                        2 => (used, 2),
                        3 => (Used { id: 7, ..used }, status),
                        4 => (
                            Used {
                                len: used.len.saturating_sub(1),
                                ..used
                            },
                            status,
                        ),
                        5 => (Used { len: 0, ..used }, status),
                        _ => (used, status),
                    }
                };
                if validate_completion(op, len as u32, 0, used.id, used.len, status).is_err() {
                    return self.fail();
                }
                crate::trace::event(8, self.serial, u64::from(used.len));
                crate::interleave::io_completed();
                if matches!(op, Operation::Flush) {
                    crate::trace::event(9, self.serial, 0);
                }
                if matches!(op, Operation::Read) {
                    // SAFETY: The serialized filesystem owner retains this static queue/request
                    // until validated completion or confirmed reset. Aligned volatile fields observe
                    // device-owned DMA; publication/completion fences order accesses and no reference
                    // to shared DMA memory survives a scheduling point.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (&raw const REQUEST.data).cast::<u8>(),
                            data.as_mut_ptr(),
                            len,
                        );
                    }
                }
                return Ok(());
            }
            if arch::now() < start || arch::now() >= deadline {
                return self.fail();
            }
            crate::process::io_progress();
        }
    }
    fn fail<T>(&mut self) -> Result<T> {
        self.failed = true;
        crate::diagnostics::event("virtio", "DEVICE_FAILED", 0, 0);
        // SAFETY: DTB-validated aperture is mapped supervisor-only for this device.
        // Constructor retains no Rust reference; each register access checks its bounds.
        let d = unsafe { Mmio::new(self.base, self.aperture) };
        d.write(0x70, 0);
        let start = arch::now();
        loop {
            let reset = d.read(0x70);
            #[cfg(feature = "instrumented")]
            let reset = if TEST_ACTIVE.load(Ordering::Acquire) == 7 {
                1
            } else {
                reset
            };
            if reset == 0 {
                arch::fence();
                #[cfg(feature = "instrumented")]
                TEST_ACTIVE.store(0, Ordering::Release);
                crate::diagnostics::event("virtio", "RESET_CONFIRMED", 0, 0);
                return Err(Error::Io);
            }
            if arch::now().saturating_sub(start) >= self.frequency {
                crate::diagnostics::event("virtio", "DMA_BUFFERS_RETAINED", 0, 0);
                crate::fatal("DMA_RESET_TIMEOUT");
            }
            crate::process::io_progress();
        }
    }
}
impl BlockDevice for Device {
    fn trace(&mut self, event: u64, sequence: u64) {
        crate::trace::event(event, sequence, 0);
        if (110..=113).contains(&event) {
            let code = match event {
                110 => "REPLAY_VALIDATED",
                111 => "REPLAY_HOMES_DURABLE",
                112 => "REPLAY_RETIRE",
                _ => "REPLAY_RETIRED",
            };
            crate::diagnostics::event("journal", code, 0, sequence);
        }
    }
    fn read_block(&mut self, b: u32, out: &mut Block) -> Result<()> {
        self.perform(Operation::Read, u64::from(b) * 8, out)
    }
    fn write_block(&mut self, b: u32, input: &Block) -> Result<()> {
        // perform copies this bounded scratch into its owned DMA buffer before publication.
        let mut copy = *input;
        self.perform(Operation::Write, u64::from(b) * 8, &mut copy)
    }
    fn write_commit(&mut self, input: &[u8; 512]) -> Result<()> {
        let mut copy = *input;
        self.perform(Operation::Write, 8, &mut copy)
    }
    fn flush(&mut self) -> Result<()> {
        self.perform(Operation::Flush, 0, &mut [])
    }
    fn byte_len(&self) -> u64 {
        disk_format::IMAGE_SIZE
    }
}
pub fn interrupt(irq: u32) -> bool {
    if IRQ.load(Ordering::Acquire) != irq {
        return false;
    }
    // SAFETY: DTB-validated aperture is mapped supervisor-only for this device.
    // Constructor retains no Rust reference; each register access checks its bounds.
    let d = unsafe {
        Mmio::new(
            BASE.load(Ordering::Acquire),
            APERTURE.load(Ordering::Acquire) as usize,
        )
    };
    let status = d.read(0x60);
    d.write(0x64, status);
    true
}

pub fn completed() -> bool {
    if withholding() || crate::interleave::withhold_io() {
        return false;
    }
    // SAFETY: Both indices are aligned fields of permanently retained static
    // queue memory. Volatile scalar reads coexist with device DMA and create no alias.
    unsafe {
        core::ptr::read_volatile(&raw const QUEUE.used_idx)
            == core::ptr::read_volatile(&raw const QUEUE.avail_idx)
    }
}
