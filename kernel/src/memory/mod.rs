//! Owned page tables and physical frames. All raw physical access stays here.
//! Single-hart callers hold the kernel execution token; no operation schedules
//! while a mutable table/frame reference exists. Page-table memory is never DMA.
// Indexed raw-global access avoids holding an iterator borrow across safe scheduling points.
#![allow(clippy::needless_range_loop)]
use crate::arch;
use kernel_abi::Error;
use kernel_platform::dtb::{Platform, Region};
pub const PAGE: u64 = 4096;
pub const MMIO: u64 = 0xffff_ffc1_0000_0000;
pub const STACKS: u64 = 0xffff_ffd0_0000_0000;
const POOL: u64 = 0x8800_0000;
const HEAP_BASE: u64 = 0x8400_0000;
const HEAP_SIZE: usize = 32 * 1024 * 1024;
static mut HEAP: Option<kernel_heap::Heap<'static>> = None;
const USER_FRAMES: usize = 32768;
const TABLES: usize = 4096;
const V: u64 = 1;
const R: u64 = 2;
const W: u64 = 4;
const X: u64 = 8;
const U: u64 = 16;
const A: u64 = 64;
const D: u64 = 128;
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct Page([u64; 512]);
static mut TABLE_POOL: [Page; TABLES] = [Page([0; 512]); TABLES];
static mut TABLE_OWNERS: [u16; TABLES] = [0; TABLES];
static mut OWNERS: [u16; USER_FRAMES] = [0; USER_FRAMES];
static mut USER_BUSY: [u64; USER_FRAMES / 64] = [0; USER_FRAMES / 64];
static mut TABLE_BUSY: [u64; TABLES / 64] = [0; TABLES / 64];
static mut ROOT: u64 = 0;
#[repr(C, align(4096))]
struct KernelStacks([u8; 65 * 16384]);
static mut KERNEL_STACKS: KernelStacks = KernelStacks([0; 65 * 16384]);
unsafe extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}
fn frame_ptr(pa: u64) -> *mut u8 {
    pa as *mut u8
}
fn table_ptr(pa: u64) -> *mut [u64; 512] {
    pa as *mut [u64; 512]
}
fn alloc_table(owner: u16) -> Result<u64, Error> {
    // SAFETY: callers are serial on one hart, with no table references across scheduling.
    unsafe {
        for i in 0..TABLES {
            if TABLE_BUSY[i / 64] & (1u64 << (i % 64)) == 0 {
                if TABLE_OWNERS[i] != 0 {
                    crate::fatal("TABLE_BITMAP");
                }
                TABLE_BUSY[i / 64] |= 1u64 << (i % 64);
                TABLE_OWNERS[i] = owner;
                let p = (&raw mut TABLE_POOL).cast::<Page>().add(i);
                (*p).0.fill(0);
                return Ok(p as u64);
            }
        }
    }
    Err(Error::NoMemory)
}
// Remove empty branches after a failed admission or exact unmap. A table is
// released only after its parent entry is invalidated and stale walks fenced.
fn free_table(pa: u64, owner: u16) {
    let start = (&raw mut TABLE_POOL).cast::<Page>() as u64;
    if pa < start || pa >= start + TABLES as u64 * PAGE || !(pa - start).is_multiple_of(PAGE) {
        crate::fatal("TABLE_RANGE");
    }
    let index = ((pa - start) / PAGE) as usize;
    // SAFETY: the parent no longer references this table and sfence.vma has
    // completed. The only hart owns allocator metadata throughout this call.
    unsafe {
        if TABLE_OWNERS[index] != owner {
            crate::fatal("TABLE_OWNER");
        }
        (*table_ptr(pa)).fill(0);
        TABLE_OWNERS[index] = 0;
        TABLE_BUSY[index / 64] &= !(1u64 << (index % 64));
    }
}
fn prune(root: u64, owner: u16, va: u64) {
    let upper = ((va >> 30) & 511) as usize;
    let middle = ((va >> 21) & 511) as usize;
    // SAFETY: caller supplies a live owned root, and all intermediate entries
    // were installed by map. No process can execute during this operation.
    unsafe {
        let first = (*table_ptr(root))[upper];
        if first & V == 0 || first & (R | W | X) != 0 {
            return;
        }
        let branch = (first >> 10) << 12;
        let second = (*table_ptr(branch))[middle];
        if second & V != 0 && second & (R | W | X) == 0 {
            let leaf = (second >> 10) << 12;
            if (*table_ptr(leaf)).iter().all(|entry| *entry == 0) {
                (*table_ptr(branch))[middle] = 0;
                arch::translation_fence();
                free_table(leaf, owner);
            }
        }
        if (*table_ptr(branch)).iter().all(|entry| *entry == 0) {
            (*table_ptr(root))[upper] = 0;
            arch::translation_fence();
            free_table(branch, owner);
        }
    }
}
fn pte(root: u64, va: u64, create: bool, owner: u16) -> Result<*mut u64, Error> {
    let mut table = root;
    for shift in [30, 21] {
        let i = ((va >> shift) & 511) as usize;
        // SAFETY: root and children originate only in TABLE_POOL; entries are never user writable.
        let entry = unsafe { (*table_ptr(table))[i] };
        if entry & V == 0 {
            if !create {
                return Err(Error::Fault);
            }
            let next = match alloc_table(owner) {
                Ok(next) => next,
                Err(error) => {
                    prune(root, owner, va);
                    return Err(error);
                }
            };
            // SAFETY: The root and every traversed child are aligned live TABLE_POOL pages;
            // indices are masked to 0..512 and no table borrow crosses a scheduling point.
            unsafe {
                (*table_ptr(table))[i] = (next >> 12) << 10 | V;
            }
            table = next;
        } else {
            if entry & (R | W | X) != 0 {
                return Err(Error::Fault);
            }
            table = (entry >> 10) << 12;
        }
    }
    // SAFETY: The root and every traversed child are aligned live TABLE_POOL pages;
    // indices are masked to 0..512 and no table borrow crosses a scheduling point.
    Ok(unsafe {
        (*table_ptr(table))
            .as_mut_ptr()
            .add(((va >> 12) & 511) as usize)
    })
}
fn map(root: u64, va: u64, pa: u64, flags: u64, owner: u16) -> Result<(), Error> {
    if (va | pa) & 4095 != 0 {
        return Err(Error::Invalid);
    }
    let slot = pte(root, va, true, owner)?;
    // SAFETY: pte returned an aligned slot in an owned table. The sole hart holds
    // the nonpreemptive kernel token; the write publishes only validated page geometry.
    unsafe {
        if *slot & V != 0 {
            return Err(Error::Invalid);
        }
        *slot = (pa >> 12) << 10 | flags | V | A | if flags & W != 0 { D } else { 0 };
    }
    Ok(())
}
pub fn init(platform: &Platform, dtb: Region) -> Result<(), Error> {
    let end = &raw const __kernel_end as u64;
    if end >= HEAP_BASE {
        return Err(Error::NoMemory);
    }
    let root = alloc_table(u16::MAX)?;
    // SAFETY: Boot runs before scheduler/interrupt admission. These bounded static
    // metadata accesses reserve validated RAM; no other owner can observe partial setup.
    unsafe {
        ROOT = root;
    }
    let text = &raw const __text_end as u64;
    let ro = &raw const __rodata_end as u64;
    let start = &raw const __kernel_start as u64;
    if core::iter::once(dtb)
        .chain(platform.reserved[..platform.reserved_count].iter().copied())
        .any(|region| {
            (region.base < end && start < region.base.saturating_add(region.size))
                || (region.base < HEAP_BASE + HEAP_SIZE as u64
                    && HEAP_BASE < region.base.saturating_add(region.size))
        })
    {
        return Err(Error::Invalid);
    }
    // Firmware is deliberately absent from the identity map.
    for pa in (start..platform.ram.base + platform.ram.size).step_by(4096) {
        let flags = if pa < text {
            R | X
        } else if pa < ro {
            R
        } else {
            R | W
        };
        map(root, pa, pa, flags, u16::MAX)?;
    }
    for region in core::iter::once(platform.uart.region)
        .chain(core::iter::once(platform.plic))
        .chain(
            platform.virtio[..platform.virtio_count]
                .iter()
                .map(|d| d.region),
        )
    {
        let end = region
            .end()
            .ok_or(Error::Invalid)?
            .checked_add(4095)
            .ok_or(Error::Invalid)?
            & !4095;
        for pa in (region.base & !4095..end).step_by(4096) {
            map(root, MMIO + pa, pa, R | W, u16::MAX)?;
        }
    }
    let stack_phys = (&raw mut KERNEL_STACKS).cast::<u8>() as u64;
    for i in 0..65u64 {
        for n in 0..4u64 {
            map(
                root,
                STACKS + i * 20480 + 4096 + n * 4096,
                stack_phys + i * 16384 + n * 4096,
                R | W,
                u16::MAX,
            )?;
        }
    }
    for i in 0..USER_FRAMES {
        let r = Region {
            base: POOL + i as u64 * PAGE,
            size: PAGE,
        };
        let reserved = core::iter::once(dtb)
            .chain(platform.reserved[..platform.reserved_count].iter().copied())
            .any(|other| {
                r.base < other.base.saturating_add(other.size) && other.base < r.base + PAGE
            });
        if reserved {
            // SAFETY: Boot runs before scheduler/interrupt admission. These bounded static
            // metadata accesses reserve validated RAM; no other owner can observe partial setup.
            unsafe {
                OWNERS[i] = u16::MAX;
                USER_BUSY[i / 64] |= 1u64 << (i % 64);
            }
        }
    }
    // SAFETY: validated RAM geometry and reserved ranges establish exclusive
    // ownership of this supervisor-only arena; no user frame or DMA uses it.
    unsafe {
        let storage = core::slice::from_raw_parts_mut(HEAP_BASE as *mut u8, HEAP_SIZE);
        HEAP = Some(kernel_heap::Heap::new(storage).map_err(|_| Error::NoMemory)?);
    }
    let excluded = (0..USER_FRAMES)
        // SAFETY: Boot runs before scheduler/interrupt admission. These bounded static
        // metadata accesses reserve validated RAM; no other owner can observe partial setup.
        .filter(|i| unsafe { OWNERS[*i] == u16::MAX })
        .count();
    crate::log!(
        "MEMORY bytes firmware={} image={} heap={} user_pool={} excluded_user_pages={} dtb={} reserve={}\n",
        start - platform.ram.base,
        end - start,
        HEAP_SIZE,
        USER_FRAMES * 4096,
        excluded,
        dtb.size,
        platform.ram.size
            - (start - platform.ram.base)
            - (end - start)
            - HEAP_SIZE as u64
            - USER_FRAMES as u64 * PAGE
    );
    // Early UART still uses its physical aperture until the caller rebinds it.
    if !arch::activate(root) {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub fn kernel_root() -> u64 {
    // SAFETY: Boot initializes this scalar before user admission; it is immutable
    // afterward, and no Rust reference to the global is created.
    unsafe { ROOT }
}
pub fn stack_top(slot: usize) -> u64 {
    STACKS + slot as u64 * 20480 + 20480
}
pub fn new_root(owner: u16) -> Result<u64, Error> {
    let root = alloc_table(owner)?;
    let kernel = kernel_root();
    // Share only supervisor entries; users occupy root[0].
    // SAFETY: Both roots are aligned live TABLE_POOL pages. The new root is private;
    // only supervisor entries are copied and no scheduling or DMA touches either table.
    unsafe {
        for i in 1..512 {
            (*table_ptr(root))[i] = (*table_ptr(kernel))[i];
        }
    }
    Ok(root)
}
fn alloc_frame(owner: u16) -> Result<u64, Error> {
    // SAFETY: bitmap/tag reservations are serial on the sole hart. No user is
    // admitted to this frame until it is zeroed and mapped by its only owner.
    unsafe {
        for word in 0..USER_FRAMES / 64 {
            let free = !USER_BUSY[word];
            if free == 0 {
                continue;
            }
            let bit = free.trailing_zeros() as usize;
            let index = word * 64 + bit;
            if OWNERS[index] != 0 {
                crate::fatal("FRAME_BITMAP");
            }
            USER_BUSY[word] |= 1u64 << bit;
            OWNERS[index] = owner;
            let pa = POOL + index as u64 * PAGE;
            core::ptr::write_bytes(frame_ptr(pa), 0, 4096);
            return Ok(pa);
        }
    }
    Err(Error::NoMemory)
}
pub fn allocate(root: u64, owner: u16, va: u64, pages: u64) -> Result<(), Error> {
    let end = pages
        .checked_mul(PAGE)
        .and_then(|size| va.checked_add(size))
        .ok_or(Error::Invalid)?;
    if owner == 0
        || owner == u16::MAX
        || pages == 0
        || !va.is_multiple_of(PAGE)
        || va < 0x10000
        || end > 0x40000000
    {
        return Err(Error::Invalid);
    }
    let mut done = 0;
    while done < pages {
        match alloc_frame(owner).and_then(|pa| {
            if let Err(e) = map(root, va + done * PAGE, pa, R | W | U, owner) {
                release_frame(pa, owner);
                return Err(e);
            }
            Ok(())
        }) {
            Ok(()) => done += 1,
            Err(e) => {
                for n in 0..done {
                    unmap(root, owner, va + n * PAGE);
                }
                return Err(e);
            }
        }
    }
    arch::translation_fence();
    Ok(())
}
fn release_frame(pa: u64, owner: u16) {
    if !(POOL..POOL + USER_FRAMES as u64 * PAGE).contains(&pa) {
        crate::fatal("FRAME_RANGE");
    }
    let index = ((pa - POOL) / PAGE) as usize;
    // SAFETY: The checked pool index belongs to this owner, and its user PTE is
    // already invalidated. Kernel-alias updates and zeroing finish before bitmap reuse.
    unsafe {
        if OWNERS[index] != owner {
            crate::fatal("FRAME_OWNER");
        }
    }
    // No user translation survives this point. Restore writable supervisor alias.
    let alias =
        pte(kernel_root(), pa, false, u16::MAX).unwrap_or_else(|_| crate::fatal("FRAME_ALIAS"));
    // SAFETY: The checked pool index belongs to this owner, and its user PTE is
    // already invalidated. Kernel-alias updates and zeroing finish before bitmap reuse.
    unsafe {
        *alias |= W | D;
    }
    arch::translation_fence();
    // SAFETY: The checked pool index belongs to this owner, and its user PTE is
    // already invalidated. Kernel-alias updates and zeroing finish before bitmap reuse.
    unsafe {
        core::ptr::write_bytes(frame_ptr(pa), 0, 4096);
        OWNERS[index] = 0;
        USER_BUSY[index / 64] &= !(1u64 << (index % 64));
    }
}
pub fn unmap(root: u64, owner: u16, va: u64) {
    if let Ok(p) = pte(root, va, false, owner) {
        // SAFETY: pte returned a live aligned slot in the current owner root. User mode
        // cannot run during invalidation, and full sfence precedes physical-frame release.
        let entry = unsafe { *p };
        if entry & V != 0 {
            // SAFETY: pte returned a live aligned slot in the current owner root. User mode
            // cannot run during invalidation, and full sfence precedes physical-frame release.
            unsafe {
                *p = 0;
            }
            arch::translation_fence();
            release_frame((entry >> 10) << 12, owner);
            prune(root, owner, va);
        }
    }
}
pub fn protect(root: u64, va: u64, executable: bool, writable: bool) -> Result<(), Error> {
    if executable && writable {
        return Err(Error::Invalid);
    }
    let p = pte(root, va, false, 0)?;
    // SAFETY: The loader exclusively owns this unpublished address space; aligned
    // table slots come from pte, and permission changes precede translation/fetch fences.
    let entry = unsafe { *p };
    if entry & V == 0 {
        return Err(Error::Fault);
    }
    let pa = (entry >> 10) << 12;
    // SAFETY: The loader exclusively owns this unpublished address space; aligned
    // table slots come from pte, and permission changes precede translation/fetch fences.
    unsafe {
        *p = (entry & !255)
            | V
            | R
            | U
            | A
            | if executable { X } else { 0 }
            | if writable { W | D } else { 0 };
    }
    if executable {
        let alias = pte(kernel_root(), pa, false, 0)?;
        // SAFETY: The loader exclusively owns this unpublished address space; aligned
        // table slots come from pte, and permission changes precede translation/fetch fences.
        unsafe {
            *alias &= !(W | X | D);
        }
    }
    arch::translation_fence();
    arch::instruction_fence();
    Ok(())
}
pub fn physical(root: u64, va: u64, write: bool) -> Result<u64, Error> {
    let slot = pte(root, va, false, 0)?;
    // SAFETY: pte walks only kernel-owned tables. Reading this aligned scalar
    // creates no lasting borrow; user permission bits are checked before returning a PA.
    let e = unsafe { *slot };
    if e & (V | U | R) != (V | U | R) || (write && e & W == 0) {
        return Err(Error::Fault);
    }
    Ok(((e >> 10) << 12) | (va & 4095))
}
pub fn validate(root: u64, address: u64, len: usize, write: bool) -> Result<(), Error> {
    kernel_core::memory::validate_range(
        address,
        len as u64,
        if write {
            kernel_core::memory::Access::Write
        } else {
            kernel_core::memory::Access::Read
        },
        |page, access| {
            physical(
                root,
                page,
                matches!(access, kernel_core::memory::Access::Write),
            )
            .is_ok()
        },
    )
}
pub fn copy_in(root: u64, address: u64, out: &mut [u8]) -> Result<(), Error> {
    validate(root, address, out.len(), false)?;
    let mut done = 0;
    while done < out.len() {
        let pa = physical(root, address + done as u64, false)?;
        let n = (4096 - (pa as usize & 4095)).min(out.len() - done);
        // SAFETY: The complete user range and each PTE were validated; the process
        // cannot alter mappings while in S-mode. Kernel output and user frames are disjoint,
        // byte-aligned, live for this non-scheduling copy, and n stays inside both ranges.
        unsafe {
            core::ptr::copy_nonoverlapping(frame_ptr(pa), out[done..].as_mut_ptr(), n);
        }
        done += n;
    }
    Ok(())
}
pub fn copy_out(root: u64, address: u64, input: &[u8]) -> Result<(), Error> {
    validate(root, address, input.len(), true)?;
    let mut done = 0;
    while done < input.len() {
        let pa = physical(root, address + done as u64, true)?;
        let n = (4096 - (pa as usize & 4095)).min(input.len() - done);
        // SAFETY: Full writable user-range validation precedes every copy. Kernel
        // input and owned user frames are disjoint/live, byte alignment suffices, and no
        // scheduler or interrupt can mutate this process mapping during the bounded copy.
        unsafe {
            core::ptr::copy_nonoverlapping(input[done..].as_ptr(), frame_ptr(pa), n);
        }
        done += n;
    }
    Ok(())
}
pub fn release(owner: u16, root: u64) {
    // First remove all user translations as one operation. The process cannot run.
    // SAFETY: This process is no longer running in its user root. All root/frame
    // pointers originate from owned pools; scalar/table borrows end before cleanup yields
    // and full translation invalidation precedes any frame/table ownership reuse.
    unsafe {
        (*table_ptr(root))[0] = 0;
    }
    arch::translation_fence();
    let mut reclaimed = 0usize;
    for i in 0..USER_FRAMES {
        // SAFETY: This process is no longer running in its user root. All root/frame
        // pointers originate from owned pools; scalar/table borrows end before cleanup yields
        // and full translation invalidation precedes any frame/table ownership reuse.
        if unsafe { OWNERS[i] } == owner {
            release_frame(POOL + i as u64 * PAGE, owner);
            reclaimed += 1;
            if reclaimed.is_multiple_of(64) {
                // No frame/table reference or allocator borrow crosses this
                // explicit scheduler point. The process slot remains occupied.
                crate::process::cleanup_progress();
            }
        }
    }
    // SAFETY: This process is no longer running in its user root. All root/frame
    // pointers originate from owned pools; scalar/table borrows end before cleanup yields
    // and full translation invalidation precedes any frame/table ownership reuse.
    unsafe {
        for i in 0..TABLES {
            if TABLE_OWNERS[i] == owner {
                TABLE_OWNERS[i] = 0;
                TABLE_BUSY[i / 64] &= !(1u64 << (i % 64));
            }
        }
    }
}

pub fn heap_allocate(
    length: usize,
    alignment: usize,
) -> Result<kernel_heap::Allocation<'static>, Error> {
    let on = arch::disable();
    // SAFETY: no schedule point or interrupt can retain a second heap borrow.
    let result = unsafe {
        (&mut *(&raw mut HEAP))
            .as_mut()
            .ok_or(Error::NoMemory)
            .and_then(|heap| {
                heap.allocate(length, alignment)
                    .map_err(|_| Error::NoMemory)
            })
    };
    arch::restore(on);
    result
}

#[cfg(feature = "instrumented")]
pub fn owner_counts() -> [u64; 3] {
    // This observation does not schedule. Interrupts never change allocation ownership.
    // SAFETY: This read-only census never schedules; interrupts do not allocate
    // frames, tables or heap owners. Aligned static borrows remain local to this block.
    let user = unsafe {
        (&*(&raw const OWNERS))
            .iter()
            .filter(|owner| **owner != 0 && **owner != u16::MAX)
            .count() as u64
    };
    // SAFETY: This read-only census never schedules; interrupts do not allocate
    // frames, tables or heap owners. Aligned static borrows remain local to this block.
    let tables = unsafe {
        (&*(&raw const TABLE_OWNERS))
            .iter()
            .filter(|owner| **owner != 0)
            .count() as u64
    };
    // SAFETY: This read-only census never schedules; interrupts do not allocate
    // frames, tables or heap owners. Aligned static borrows remain local to this block.
    let free = unsafe {
        (&*(&raw const HEAP))
            .as_ref()
            .map_or(0, |heap| heap.free_bytes() as u64)
    };
    [user, tables, free]
}

#[cfg(feature = "instrumented")]
pub fn user_pool_counts() -> [u64; 4] {
    let mut counts = [USER_FRAMES as u64, 0, 0, 0];
    // SAFETY: this bounded read never schedules; interrupt handlers never mutate frame ownership.
    for owner in unsafe { &*(&raw const OWNERS) } {
        counts[match *owner {
            u16::MAX => 1,
            0 => 3,
            _ => 2,
        }] += 1;
    }
    counts
}
