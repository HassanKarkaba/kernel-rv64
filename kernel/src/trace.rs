//! Optional bounded binary trace. No payload bytes or addresses are recorded.
//! Event numbers: 1 enqueue, 2 dispatch, 3 block, 4 wake, 5 user-return,
//! 6 exit, 7 I/O submit, 8 I/O complete, 9 flush complete, 20.. journal.
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn event(_: u64, _: u64, _: u64) {}

#[cfg(feature = "instrumented")]
mod enabled {
    use crate::{arch, memory, process};
    use core::sync::atomic::{AtomicBool, Ordering};
    use kernel_abi::Error;
    const CAPACITY: usize = 8192;
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static mut RECORDS: [[u64; 5]; CAPACITY] = [[0; 5]; CAPACITY];
    static mut NEXT: u64 = 0;
    static mut LOST: u64 = 0;
    pub fn event(kind: u64, object: u64, detail: u64) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let on = arch::disable();
        // SAFETY: the sole hart cannot schedule or interrupt while these aligned
        // static records are borrowed. All borrows end before restoring SIE.
        unsafe {
            let index = NEXT as usize % CAPACITY;
            NEXT = NEXT.saturating_add(1);
            if NEXT > CAPACITY as u64 {
                LOST = LOST.saturating_add(1);
            }
            RECORDS[index] = [NEXT, arch::now(), kind, object, detail];
        }
        arch::restore(on);
    }
    pub fn control(op: u64, pointer: u64, count: u64, offset: u64) -> Result<u64, Error> {
        match op {
            0 | 1 if pointer == 0 && count == 0 && offset == 0 => {
                ACTIVE.store(false, Ordering::Relaxed);
                if op == 0 {
                    // SAFETY: disabled collection and nonpreemptive S-mode give
                    // this scalar reset exclusive access; no pointers escape.
                    unsafe {
                        NEXT = 0;
                        LOST = 0;
                    }
                    ACTIVE.store(true, Ordering::Relaxed);
                }
                Ok(0)
            }
            2 if count == 0 && offset == 0 => {
                if ACTIVE.load(Ordering::Relaxed) {
                    return Err(Error::Busy);
                }
                let mut out = [0u8; 32];
                // SAFETY: collection is disabled; these static scalar reads do
                // not schedule or alias mutable references.
                let values = unsafe { [1, NEXT.min(CAPACITY as u64), LOST, crate::frequency()] };
                for (i, value) in values.iter().enumerate() {
                    out[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
                }
                memory::copy_out(process::root(), pointer, &out)?;
                Ok(0)
            }
            3 if count <= 100 => {
                if ACTIVE.load(Ordering::Relaxed) {
                    return Err(Error::Busy);
                }
                // SAFETY: collection is stopped, static records remain valid,
                // bounds checked before indexing, and no references escape.
                let total = unsafe { NEXT.min(CAPACITY as u64) };
                if offset.checked_add(count).is_none_or(|end| end > total) {
                    return Err(Error::Invalid);
                }
                memory::validate(process::root(), pointer, count as usize * 40, true)?;
                for i in 0..count {
                    // SAFETY: capture is stopped and the checked index lies in the static ring.
                    let record = unsafe {
                        RECORDS
                            [((NEXT.saturating_sub(total) + offset + i) % CAPACITY as u64) as usize]
                    };
                    let mut bytes = [0u8; 40];
                    for (j, value) in record.iter().enumerate() {
                        bytes[j * 8..j * 8 + 8].copy_from_slice(&value.to_le_bytes());
                    }
                    memory::copy_out(process::root(), pointer + i * 40, &bytes)?;
                }
                Ok(count)
            }
            _ => Err(Error::Invalid),
        }
    }
}
#[cfg(feature = "instrumented")]
pub use enabled::{control, event};
