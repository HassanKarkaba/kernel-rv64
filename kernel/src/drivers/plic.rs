use super::Mmio;
use kernel_platform::dtb::Platform;
static mut BASE: u64 = 0;
static mut APERTURE: usize = 0;
static mut CONTEXT: usize = 0;
static mut UART: u32 = 0;
pub fn init(p: &Platform) {
    let base = crate::memory::MMIO + p.plic.base;
    // SAFETY: boot initializes these aligned scalars before SIE is enabled;
    // subsequent ISR reads occur with SIE clear. The mapped DTB aperture and
    // validated context bound every MMIO access; no Rust reference escapes.
    let dev = unsafe { Mmio::new(base, p.plic.size as usize) };
    // SAFETY: boot initializes these aligned scalars before SIE is enabled;
    // subsequent ISR reads occur with SIE clear. The mapped DTB aperture and
    // validated context bound every MMIO access; no Rust reference escapes.
    unsafe {
        BASE = base;
        APERTURE = p.plic.size as usize;
        CONTEXT = p.plic_context as usize;
        UART = p.uart.irq;
    }
    let context = p.plic_context as usize;
    for word in 0..32 {
        dev.write(0x2000 + context * 0x80 + word * 4, 0);
    }
    for irq in core::iter::once(p.uart.irq).chain(p.virtio[..p.virtio_count].iter().map(|d| d.irq))
    {
        dev.write(irq as usize * 4, 1);
        let offset = 0x2000 + context * 0x80 + (irq as usize / 32) * 4;
        dev.write(offset, dev.read(offset) | (1 << (irq % 32)));
    }
    dev.write(0x200000 + context * 0x1000, 0);
}
pub fn interrupt() {
    // SAFETY: boot initializes these aligned scalars before SIE is enabled;
    // subsequent ISR reads occur with SIE clear. The mapped DTB aperture and
    // validated context bound every MMIO access; no Rust reference escapes.
    let dev = unsafe { Mmio::new(BASE, APERTURE) };
    // SAFETY: boot initializes these aligned scalars before SIE is enabled;
    // subsequent ISR reads occur with SIE clear. The mapped DTB aperture and
    // validated context bound every MMIO access; no Rust reference escapes.
    let context = unsafe { CONTEXT };
    let offset = 0x200004 + context * 0x1000;
    let irq = dev.read(offset);
    if irq == 0 {
        return;
    }
    // SAFETY: boot initializes these aligned scalars before SIE is enabled;
    // subsequent ISR reads occur with SIE clear. The mapped DTB aperture and
    // validated context bound every MMIO access; no Rust reference escapes.
    if irq == unsafe { UART } {
        super::uart::service();
    } else if !super::virtio::interrupt(irq) {
        let mask = 0x2000 + context * 0x80 + (irq as usize / 32) * 4;
        if irq < 1024 {
            dev.write(mask, dev.read(mask) & !(1 << (irq % 32)));
        }
        crate::diagnostics::event("plic", "UNKNOWN_MASKED", 0, u64::from(irq));
    }
    dev.write(offset, irq);
}
