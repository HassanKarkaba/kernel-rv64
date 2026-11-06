//! Instrumented semantic-window controls. Release contains only inline no-ops.
//! Protected windows are observed, never opened. Scalar state is atomic because
//! the timer observer may interrupt ordinary S-mode; reset/phase publication is
//! masked where several fields form one observable transition.
#[cfg(feature = "instrumented")]
mod enabled {
    use crate::{arch, process, trace};
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use kernel_abi::Error;
    static DOMAIN: AtomicU64 = AtomicU64::new(0);
    static MODE: AtomicU64 = AtomicU64::new(0);
    static PHASE: AtomicU64 = AtomicU64::new(0);
    fn selected(domain: u64) -> bool {
        DOMAIN.load(Relaxed) == domain && process::pid().raw() == 257
    }
    pub fn control(domain: u64, mode: u64) -> Result<u64, Error> {
        if domain > 5 || mode > 1 || domain >= 4 && mode != 0 {
            return Err(Error::Invalid);
        }
        let on = arch::disable();
        DOMAIN.store(domain, Relaxed);
        MODE.store(mode, Relaxed);
        PHASE.store(0, Relaxed);
        if domain == 4 {
            trace::event(30, 257, 40);
            PHASE.store(1, Relaxed);
        }
        arch::restore(on);
        if domain == 4 {
            // Deliberately long S-mode test work owns no shared object. IRQs
            // stay enabled; a ready peer must await ordinary user-return.
            let begin = arch::now();
            while arch::now().saturating_sub(begin) < crate::frequency() / 1000 * 12 {
                core::hint::spin_loop();
            }
            let on = arch::disable();
            trace::event(37, 257, 4);
            PHASE.store(4, Relaxed);
            arch::restore(on);
        }
        Ok(0)
    }
    pub fn shutdown_wait() {
        if selected(5) {
            PHASE.store(1, Relaxed);
            crate::diagnostics::event("test", "SHUTDOWN_OBSERVER_WAIT", 257, 0);
            // Called after flag publication with no FS guard or masked region.
            // The existing global shutdown deadline still bounds this wait.
            process::block(process::WaitReason::Observation);
        }
    }
    pub fn shutdown_rejected() {
        if DOMAIN.load(Relaxed) == 5 && PHASE.load(Relaxed) == 1 {
            PHASE.store(2, Relaxed);
            crate::diagnostics::event("test", "SHUTDOWN_WAITER_RECHECK", process::pid().raw(), 0);
            process::wake_all(process::WaitReason::Observation);
        }
    }
    pub fn timer(from_user: bool) {
        if DOMAIN.load(Relaxed) == 4 && PHASE.load(Relaxed) == 1 {
            trace::event(36, 257, u64::from(from_user));
        }
    }
    pub fn before(domain: u64) {
        if !selected(domain) || PHASE.load(Relaxed) != 0 {
            return;
        }
        PHASE.store(1, Relaxed);
        let mode = MODE.load(Relaxed);
        trace::event(30, 257, domain * 10 + mode);
        // Callers have ended shared borrows and hold no masked critical section.
        if mode == 0 && domain != 3 {
            process::yield_now();
        }
    }
    pub fn checked(domain: u64) {
        if !selected(domain) || PHASE.load(Relaxed) != 1 {
            return;
        }
        PHASE.store(2, Relaxed);
        trace::event(31, 257, domain);
    }
    pub fn registered(reason: u64) {
        let domain = match reason {
            4 => 3,
            6 => 2,
            0x100..=0x13f => 1,
            _ => return,
        };
        if !selected(domain) || PHASE.load(Relaxed) != 2 {
            return;
        }
        // BLOCKED is already published. The ordinary context switch, not this
        // hook, is the next legal scheduling point.
        PHASE.store(3, Relaxed);
        trace::event(32, 257, domain);
    }
    pub fn waking(pid: u64) {
        let domain = DOMAIN.load(Relaxed);
        if pid == 257 && domain != 0 && PHASE.load(Relaxed) == 3 {
            trace::event(33, pid, domain);
            PHASE.store(4, Relaxed);
        }
    }
    pub fn returning() {
        let domain = DOMAIN.load(Relaxed);
        if process::pid().raw() == 257 && domain != 0 && (1..=4).contains(&PHASE.load(Relaxed)) {
            trace::event(34, 257, domain);
            PHASE.store(5, Relaxed);
        }
    }
    pub fn withhold_io() -> bool {
        // Scheduler polling has no CURRENT process. Init already owns the
        // serialized real request; phase3 exposes its unchanged DMA result.
        DOMAIN.load(Relaxed) == 3
            && MODE.load(Relaxed) == 1
            && (1..3).contains(&PHASE.load(Relaxed))
    }
    pub fn io_completed() {
        if DOMAIN.load(Relaxed) == 3 && MODE.load(Relaxed) == 0 && PHASE.load(Relaxed) == 2 {
            PHASE.store(4, Relaxed);
        }
    }
    pub fn io_before_check() {
        if !selected(3) {
            return;
        }
        if MODE.load(Relaxed) == 0 && PHASE.load(Relaxed) == 1 {
            let begin = arch::now();
            while !crate::drivers::virtio::completed() {
                if arch::now().saturating_sub(begin) >= crate::frequency() * 5 {
                    crate::fatal("INTERLEAVE_IO_TIMEOUT");
                }
                core::hint::spin_loop();
            }
            trace::event(35, 257, 3);
        }
        checked(3);
    }
}
#[cfg(feature = "instrumented")]
pub use enabled::*;
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn before(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn checked(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn registered(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn waking(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn returning() {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn withhold_io() -> bool {
    false
}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn io_before_check() {}

#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn io_completed() {}

#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn timer(_: bool) {}

#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn shutdown_wait() {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn shutdown_rejected() {}
