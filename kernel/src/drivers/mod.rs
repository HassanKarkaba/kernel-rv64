pub mod plic;
pub mod uart;
pub mod virtio;
/// Constructed only from validated DTB resources after the supervisor mapping exists.
pub struct Mmio {
    base: usize,
    size: usize,
}
impl Mmio {
    /// # Safety
    /// The caller must supply a mapped live supervisor device aperture; every
    /// size must be the validated aperture length. No user
    /// address may reach this constructor. MMIO cannot alias ordinary Rust data.
    pub unsafe fn new(base: u64, size: usize) -> Self {
        Self {
            base: base as usize,
            size,
        }
    }
    fn address(&self, offset: usize) -> usize {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.size) {
            crate::fatal("MMIO_BOUNDS");
        }
        self.base
            .checked_add(offset)
            .unwrap_or_else(|| crate::fatal("MMIO_RANGE"))
    }
    pub fn read(&self, offset: usize) -> u32 {
        // SAFETY: driver constant offsets are aligned and inside its validated device aperture.
        unsafe { core::ptr::read_volatile(self.address(offset) as *const u32) }
    }
    pub fn write(&self, offset: usize, value: u32) {
        // SAFETY: address checks the aligned offset against the constructor aperture;
        // volatile device writes create no Rust reference or alias.
        unsafe {
            core::ptr::write_volatile(self.address(offset) as *mut u32, value);
        }
    }
}
