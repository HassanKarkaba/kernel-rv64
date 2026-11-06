//! Instrumented guest-time accounting. This module is absent from the release
//! data path. A counter interval starts at reset and stops at its fixed deadline,
//! regardless of how long the supervisor waits to retrieve the observations.
#[cfg(feature = "instrumented")]
mod measured {
    use crate::arch;
    use kernel_abi::Error;
    #[derive(Clone, Copy)]
    struct Record {
        pid: u64,
        user_ticks: u64,
        dispatches: u64,
        max_gap: u64,
        first: u64,
        last: u64,
        entered: u64,
    }
    impl Record {
        const EMPTY: Self = Self {
            pid: 0,
            user_ticks: 0,
            dispatches: 0,
            max_gap: 0,
            first: 0,
            last: 0,
            entered: 0,
        };
    }
    static mut RECORDS: [Record; 8] = [Record::EMPTY; 8];
    static mut COUNT: usize = 0;
    static mut START: u64 = 0;
    static mut STOP: u64 = 0;
    static mut ORDINAL: u64 = 0;
    static mut TRACE: [(u64, u64); 4096] = [(0, 0); 4096];
    static mut TRACE_COUNT: usize = 0;
    static mut OVERFLOW: bool = false;
    pub fn reset(pids: &[u64]) -> Result<(), Error> {
        if !matches!(pids.len(), 4 | 8)
            || pids.iter().enumerate().any(|(i, p)| {
                kernel_core::process::Pid::decode(*p).is_err() || pids[..i].contains(p)
            })
        {
            return Err(Error::Invalid);
        }
        let start = arch::now();
        let stop = start
            .checked_add(crate::frequency().checked_mul(10).ok_or(Error::Invalid)?)
            .ok_or(Error::Invalid)?;
        // SAFETY: init owns this synchronous reset; ordinary S-mode is nonpreemptible.
        unsafe {
            RECORDS = [Record::EMPTY; 8];
            COUNT = pids.len();
            START = start;
            STOP = stop;
            ORDINAL = 0;
            TRACE_COUNT = 0;
            OVERFLOW = false;
            for (i, pid) in pids.iter().enumerate() {
                RECORDS[i].pid = *pid;
            }
        }
        Ok(())
    }
    pub fn dispatch(pid: u64) {
        let now = arch::now();
        // SAFETY: scheduler invokes this with interrupts disabled; bounded records never escape.
        unsafe {
            if now >= STOP {
                return;
            }
            for r in (&mut *(&raw mut RECORDS)).iter_mut().take(COUNT) {
                if r.pid != pid {
                    continue;
                }
                ORDINAL += 1;
                if r.last != 0 {
                    r.max_gap = r.max_gap.max(ORDINAL - r.last - 1);
                } else {
                    r.first = ORDINAL;
                }
                r.last = ORDINAL;
                r.dispatches += 1;
                if TRACE_COUNT < 4096 {
                    TRACE[TRACE_COUNT] = (pid, now);
                    TRACE_COUNT += 1;
                } else {
                    OVERFLOW = true;
                }
                break;
            }
        }
    }
    pub fn user_enter(pid: u64) {
        let now = arch::now();
        // SAFETY: called immediately before sret with interrupts disabled, on the sole hart.
        unsafe {
            for r in (&mut *(&raw mut RECORDS)).iter_mut().take(COUNT) {
                if r.pid == pid {
                    r.entered = now;
                    break;
                }
            }
        }
    }
    pub fn user_exit(pid: u64) {
        let now = arch::now();
        // SAFETY: trap entry has disabled interrupts; this copies/updates only bounded scalar records.
        unsafe {
            for r in (&mut *(&raw mut RECORDS)).iter_mut().take(COUNT) {
                if r.pid == pid {
                    if r.entered != 0 {
                        if now < r.entered {
                            crate::fatal("METRICS_CLOCK");
                        }
                        let end = now.min(STOP);
                        let begin = r.entered.max(START);
                        if end > begin {
                            r.user_ticks = r
                                .user_ticks
                                .checked_add(end - begin)
                                .unwrap_or_else(|| crate::fatal("METRICS_OVERFLOW"));
                        }
                        r.entered = 0;
                    }
                    break;
                }
            }
        }
    }
    pub fn snapshot() -> ([u8; 416], usize) {
        let mut out = [0u8; 416];
        // SAFETY: synchronous init syscall never yields; nested S-mode IRQs do not touch these records.
        unsafe {
            out[..4].copy_from_slice(&1u32.to_le_bytes());
            out[4..8].copy_from_slice(&(COUNT as u32).to_le_bytes());
            out[8..16].copy_from_slice(&START.to_le_bytes());
            out[16..24].copy_from_slice(&arch::now().min(STOP).to_le_bytes());
            out[24..32].copy_from_slice(&crate::frequency().to_le_bytes());
            for (i, r) in (&*(&raw const RECORDS)).iter().take(COUNT).enumerate() {
                for (j, v) in [
                    r.pid,
                    r.user_ticks,
                    r.dispatches,
                    r.max_gap,
                    r.first,
                    r.last,
                ]
                .iter()
                .enumerate()
                {
                    let p = 32 + i * 48 + j * 8;
                    out[p..p + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
            (out, 32 + COUNT * 48)
        }
    }
    pub fn trace(offset: usize, out: &mut [u8]) -> Result<usize, Error> {
        if !out.len().is_multiple_of(16) || out.len() > 4096 {
            return Err(Error::Invalid);
        }
        // SAFETY: no yield occurs while copying the bounded dispatch trace; ISR leaves it untouched.
        unsafe {
            if OVERFLOW {
                return Err(Error::BufferTooSmall);
            }
            if offset > TRACE_COUNT {
                return Err(Error::Invalid);
            }
            let n = (out.len() / 16).min(TRACE_COUNT - offset);
            for i in 0..n {
                let (pid, ticks) = TRACE[offset + i];
                out[i * 16..i * 16 + 8].copy_from_slice(&pid.to_le_bytes());
                out[i * 16 + 8..i * 16 + 16].copy_from_slice(&ticks.to_le_bytes());
            }
            Ok(n)
        }
    }
}
#[cfg(feature = "instrumented")]
pub use measured::{dispatch, reset, snapshot, trace, user_exit};
#[cfg(feature = "instrumented")]
pub fn user_enter(pid: u64) {
    measured::user_enter(pid);
    extended::user_enter(pid);
}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn dispatch(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn user_enter(_: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn user_exit(_: u64) {}

#[cfg(feature = "instrumented")]
mod extended {
    use crate::{arch, memory, process};
    use kernel_abi::Error;
    const SAMPLES: usize = 10_000;
    static mut WAKE_PID: u64 = 0;
    static mut WAKE_PENDING: Option<(u64, u64)> = None;
    static mut WAKE_COUNT: usize = 0;
    static mut WAKE: [(u64, u64, u64); SAMPLES] = [(0, 0, 0); SAMPLES];
    static mut CONTEXT_ACTIVE: bool = false;
    static mut CONTEXT_START: u64 = 0;
    static mut CONTEXT_COUNT: usize = 0;
    static mut CONTEXT: [u64; SAMPLES] = [0; SAMPLES];
    static mut CALIBRATION: [u64; SAMPLES] = [0; SAMPLES];
    static mut IRQ_ACTIVE: bool = false;
    static mut IRQ_BEGIN: u64 = 0;
    static mut IRQ_LABEL: &str = "none";
    static mut IRQ_LINE: u32 = 0;
    static mut IRQ_COUNT: u64 = 0;
    static mut IRQ_MAX: u64 = 0;
    static mut IRQ_MAX_LABEL: &str = "none";
    static mut IRQ_MAX_LINE: u32 = 0;
    static mut IRQ_HISTOGRAM: [u64; 7] = [0; 7];
    static mut IRQ_WINDOW_START: u64 = 0;
    fn put64(out: &mut [u8], offset: usize, value: u64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    pub fn wake(pid: u64, deadline: u64) {
        // SAFETY: scheduler wake path disables interrupts and holds no reference across dispatch.
        unsafe {
            if pid == WAKE_PID && WAKE_COUNT < SAMPLES {
                WAKE_PENDING = Some((deadline, arch::now()));
            }
        }
    }
    pub fn user_enter(pid: u64) {
        // SAFETY: sole-hart user return has interrupts disabled; sample index is explicitly bounded.
        unsafe {
            if pid == WAKE_PID
                && WAKE_COUNT < SAMPLES
                && let Some((deadline, woken)) = (&mut *(&raw mut WAKE_PENDING)).take()
            {
                WAKE[WAKE_COUNT] = (deadline, woken, arch::now());
                WAKE_COUNT += 1;
            }
        }
    }
    pub fn switch_begin() {
        // SAFETY: context-switch caller has disabled interrupts; only one switch interval is active.
        unsafe {
            if CONTEXT_ACTIVE && CONTEXT_COUNT < SAMPLES {
                CONTEXT_START = arch::now();
            }
        }
    }
    pub fn switch_end() {
        // SAFETY: resumed/initial context still has interrupts disabled and uses bounded sample storage.
        unsafe {
            if CONTEXT_ACTIVE && CONTEXT_START != 0 && CONTEXT_COUNT < SAMPLES {
                let end = arch::now();
                if end < CONTEXT_START {
                    crate::fatal("CONTEXT_CLOCK");
                }
                CONTEXT[CONTEXT_COUNT] = end - CONTEXT_START;
                CONTEXT_COUNT += 1;
                CONTEXT_START = 0;
                if CONTEXT_COUNT == SAMPLES {
                    CONTEXT_ACTIVE = false;
                }
            }
        }
    }
    pub fn irq_off(label: &'static str, line: u32) {
        // SAFETY: caller already cleared SIE; static labels outlive the recorded interval.
        unsafe {
            if IRQ_ACTIVE && IRQ_BEGIN == 0 {
                IRQ_BEGIN = arch::now();
                IRQ_LABEL = label;
                IRQ_LINE = line;
            }
        }
    }
    pub fn irq_on() {
        // SAFETY: called before setting SIE or returning via sret; all counter borrows end first.
        unsafe {
            if IRQ_ACTIVE && IRQ_BEGIN != 0 {
                let end = arch::now();
                if end < IRQ_BEGIN {
                    crate::fatal("IRQ_CLOCK");
                }
                let ticks = end - IRQ_BEGIN;
                IRQ_COUNT += 1;
                if ticks > IRQ_MAX {
                    IRQ_MAX = ticks;
                    IRQ_MAX_LABEL = IRQ_LABEL;
                    IRQ_MAX_LINE = IRQ_LINE;
                }
                let ns = u128::from(ticks) * 1_000_000_000 / u128::from(crate::frequency());
                let bucket = [1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000]
                    .iter()
                    .position(|end| ns <= *end)
                    .unwrap_or(6);
                IRQ_HISTOGRAM[bucket] += 1;
                IRQ_BEGIN = 0;
            }
        }
    }
    // Keep large export buffers in separate bounded frames even at opt-level0.
    #[inline(never)]
    fn export_wakes(pointer: u64, count: u64, offset: u64) -> Result<u64, Error> {
        if count > 128 {
            return Err(Error::Invalid);
        }
        let n = usize::try_from(offset).map_err(|_| Error::Invalid)?;
        let size = count as usize * 32;
        memory::validate(process::root(), pointer, size, true)?;
        // SAFETY: no scheduling occurs in this copy syscall; IRQs do not update wake samples.
        let available = unsafe { WAKE_COUNT };
        if n > available {
            return Err(Error::Invalid);
        }
        let actual = (count as usize).min(available - n);
        let mut out = [0u8; 4096];
        for i in 0..actual {
            // SAFETY: n+i is below the initialized sample count checked above; copy only.
            let (deadline, woken, entered) = unsafe { WAKE[n + i] };
            for (j, v) in [deadline, woken, entered, entered.saturating_sub(woken)]
                .iter()
                .enumerate()
            {
                put64(&mut out, i * 32 + j * 8, *v);
            }
        }
        memory::copy_out(process::root(), pointer, &out[..actual * 32])?;
        Ok(actual as u64)
    }
    #[inline(never)]
    fn export_contexts(pointer: u64, count: u64, offset: u64) -> Result<u64, Error> {
        if count > 256 {
            return Err(Error::Invalid);
        }
        let n = usize::try_from(offset).map_err(|_| Error::Invalid)?;
        let size = count as usize * 16;
        memory::validate(process::root(), pointer, size, true)?;
        // SAFETY: this syscall cannot schedule; context callbacks cannot change the copied count.
        let available = unsafe { CONTEXT_COUNT };
        if n > available {
            return Err(Error::Invalid);
        }
        let actual = (count as usize).min(available - n);
        let mut out = [0u8; 4096];
        for i in 0..actual {
            // SAFETY: bounded initialized context/calibration entries are copied without yielding.
            unsafe {
                put64(&mut out, i * 16, CONTEXT[n + i]);
                put64(&mut out, i * 16 + 8, CALIBRATION[n + i]);
            }
        }
        memory::copy_out(process::root(), pointer, &out[..actual * 16])?;
        Ok(actual as u64)
    }
    pub fn control(op: u64, pointer: u64, count: u64, offset: u64) -> Result<u64, Error> {
        match op {
            3 => {
                if count != 0 || offset != 0 {
                    return Err(Error::Invalid);
                }
                kernel_core::process::Pid::decode(pointer)?;
                // SAFETY: init reset never yields; scheduler/user-return hooks cannot run concurrently.
                unsafe {
                    WAKE_PID = pointer;
                    WAKE_PENDING = None;
                    WAKE_COUNT = 0;
                }
                Ok(0)
            }
            4 => export_wakes(pointer, count, offset),
            5 => {
                if pointer != 0 || count != 0 || offset != 0 {
                    return Err(Error::Invalid);
                }
                // SAFETY: synchronous init control cannot overlap a scheduler switch.
                unsafe {
                    CONTEXT_ACTIVE = false;
                    CONTEXT_START = 0;
                    CONTEXT_COUNT = 0;
                }
                // SAFETY: collection is disabled; this bounded loop never schedules and IRQs do not use it.
                for sample in unsafe { &mut *(&raw mut CALIBRATION) }.iter_mut() {
                    let begin = arch::now();
                    let end = arch::now();
                    *sample = end - begin;
                }
                // SAFETY: all calibration borrows ended before publishing collection as active.
                unsafe {
                    CONTEXT_ACTIVE = true;
                }
                Ok(0)
            }
            6 => export_contexts(pointer, count, offset),
            7 => {
                if pointer != 0 || count != 0 || offset != 0 {
                    return Err(Error::Invalid);
                }
                let on = arch::disable();
                // SAFETY: interrupts are disabled throughout reset; no IRQ hook can observe partial state.
                unsafe {
                    IRQ_ACTIVE = false;
                    IRQ_BEGIN = 0;
                    IRQ_COUNT = 0;
                    IRQ_MAX = 0;
                    IRQ_MAX_LABEL = "none";
                    IRQ_MAX_LINE = 0;
                    IRQ_HISTOGRAM = [0; 7];
                    IRQ_WINDOW_START = arch::now();
                    IRQ_ACTIVE = true;
                }
                arch::restore(on);
                Ok(0)
            }
            8 => {
                if count != 256 || offset != 0 {
                    return Err(Error::Invalid);
                }
                memory::validate(process::root(), pointer, 256, true)?;
                let on = arch::disable();
                irq_on();
                // SAFETY: disabled SIE prevents an interrupt hook racing with collection shutdown.
                unsafe {
                    IRQ_ACTIVE = false;
                }
                let mut out = [0u8; 256];
                out[..4].copy_from_slice(&1u32.to_le_bytes());
                // SAFETY: collection is stopped and SIE remains clear during the bounded snapshot copy.
                unsafe {
                    put64(&mut out, 8, IRQ_COUNT);
                    put64(&mut out, 16, IRQ_MAX);
                    put64(&mut out, 24, crate::frequency());
                    for (i, count) in (&*(&raw const IRQ_HISTOGRAM)).iter().enumerate() {
                        put64(&mut out, 32 + i * 8, *count);
                    }
                    out[88..92].copy_from_slice(&IRQ_MAX_LINE.to_le_bytes());
                    let saved_label = IRQ_MAX_LABEL;
                    let label = saved_label
                        .rsplit("/kernel/")
                        .next()
                        .unwrap_or(IRQ_MAX_LABEL);
                    let label = if label.starts_with('/') {
                        label.rsplit('/').next().unwrap_or("unknown")
                    } else {
                        label
                    };
                    let n = label.len().min(128);
                    out[92..96].copy_from_slice(&(n as u32).to_le_bytes());
                    out[96..96 + n].copy_from_slice(&label.as_bytes()[..n]);
                    put64(&mut out, 224, IRQ_WINDOW_START);
                    put64(&mut out, 232, arch::now());
                }
                arch::restore(on);
                memory::copy_out(process::root(), pointer, &out)?;
                Ok(256)
            }
            9 => {
                if count != 128 || offset != 0 {
                    return Err(Error::Invalid);
                }
                memory::validate(process::root(), pointer, 128, true)?;
                let m = memory::owner_counts();
                let p = process::owner_counts();
                let s = crate::syscall::owner_counts();
                let mut out = [0u8; 128];
                out[..4].copy_from_slice(&1u32.to_le_bytes());
                for (i, value) in m.into_iter().chain(p).chain(s).enumerate() {
                    put64(&mut out, 8 + i * 8, value);
                }
                memory::copy_out(process::root(), pointer, &out)?;
                Ok(128)
            }
            10 => {
                if count != 32 || offset != 0 {
                    return Err(Error::Invalid);
                }
                memory::validate(process::root(), pointer, 32, true)?;
                let mut out = [0; 32];
                for (i, value) in memory::user_pool_counts().iter().enumerate() {
                    put64(&mut out, i * 8, *value);
                }
                memory::copy_out(process::root(), pointer, &out)?;
                Ok(32)
            }
            _ => Err(Error::Invalid),
        }
    }
}
#[cfg(feature = "instrumented")]
pub use extended::{control, irq_off, irq_on, switch_begin, switch_end, wake};
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn wake(_: u64, _: u64) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn switch_begin() {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn switch_end() {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn irq_off(_: &'static str, _: u32) {}
#[cfg(not(feature = "instrumented"))]
#[inline(always)]
pub fn irq_on() {}
