//! Single-hart scheduler and process-owned execution resources.
//! Table borrows never cross scheduling points; queue changes disable interrupts.
//! A suspended syscall retains only its own stack and explicitly owned I/O data.
use crate::{arch, memory};
use kernel_abi::{Error, ExitRecord};
use kernel_core::{
    memory::Extents,
    process::{Descriptor, Descriptors, Pid, State, Table},
    scheduler::Queue,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    Fs,
    ConsoleRead,
    ConsoleWrite,
    PipeRead(usize),
    PipeWrite(usize),
    Io,
    Sleep(u64),
    Child,
    Shutdown,
    #[cfg(feature = "instrumented")]
    Observation,
}
impl WaitReason {
    fn code(self) -> u64 {
        match self {
            Self::Fs => 1,
            Self::ConsoleRead => 2,
            Self::ConsoleWrite => 3,
            Self::Io => 4,
            Self::Sleep(_) => 5,
            Self::Child => 6,
            Self::Shutdown => 7,
            #[cfg(feature = "instrumented")]
            Self::Observation => 8,
            Self::PipeRead(index) => 0x100 + index as u64,
            Self::PipeWrite(index) => 0x200 + index as u64,
        }
    }
}
pub struct Arguments {
    pub bytes: [u8; 1024],
    pub offsets: [usize; 16],
    pub lengths: [usize; 16],
    pub count: usize,
}
impl Arguments {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 1024],
            offsets: [0; 16],
            lengths: [0; 16],
            count: 0,
        }
    }
}
struct Execution {
    root: u64,
    context: arch::Context,
    descriptors: Descriptors,
    extents: Extents,
    pages: u32,
    wait: Option<WaitReason>,
    quantum: u64,
}
impl Execution {
    const fn new() -> Self {
        Self {
            root: 0,
            context: arch::Context::ZERO,
            descriptors: Descriptors::new(),
            extents: Extents::new(),
            pages: 0,
            wait: None,
            quantum: 0,
        }
    }
}
static mut TABLE: Option<Table> = None;
static mut EXEC: [Execution; 64] = [const { Execution::new() }; 64];
static mut READY: Queue<64> = Queue::new();
static mut CURRENT: Option<Pid> = None;
static mut SCHEDULER: arch::Context = arch::Context::ZERO;
static mut SHUTDOWN: bool = false;
static mut SHUTDOWN_DEADLINE: u64 = 0;
static mut LAST_TIME: u64 = 0;
fn table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    // SAFETY: all closures here finish before any schedule point. The ISR never
    // touches process metadata. This is an internal, single-hart execution token.
    unsafe {
        match (&mut *(&raw mut TABLE)).as_mut() {
            Some(t) => f(t),
            None => crate::fatal("PROCESS_TABLE"),
        }
    }
}
fn ready_push(pid: Pid) {
    crate::trace::event(1, pid.raw(), 0);
    // SAFETY: callers own boot or an interrupt-disabled scheduler transition; no borrow escapes.
    unsafe {
        (&mut *(&raw mut READY))
            .push(pid.raw())
            .unwrap_or_else(|_| crate::fatal("READY_QUEUE"));
    }
}
pub fn current_index() -> usize {
    pid().slot() - 1
}
pub fn pid() -> Pid {
    // SAFETY: CURRENT is a copied scalar; only explicit scheduler switches may replace it.
    unsafe { CURRENT.unwrap_or_else(|| crate::fatal("NO_CURRENT")) }
}
pub fn root() -> u64 {
    // SAFETY: the current generation owns its bounded execution slot and root.
    unsafe { EXEC[current_index()].root }
}
pub fn with_descriptors<R>(f: impl FnOnce(&mut Descriptors) -> R) -> R {
    let index = current_index();
    // SAFETY: closures are internal, never yield, and return no borrowed descriptor references.
    // Interrupt handlers never access execution descriptors.
    unsafe { f(&mut (*(&raw mut EXEC))[index].descriptors) }
}
pub fn descriptors_at<R>(index: usize, f: impl FnOnce(&mut Descriptors) -> R) -> R {
    // SAFETY: internal callers use a reserved/live slot and a non-yielding closure.
    // Descriptor borrows end before publication, cleanup, or scheduler transitions.
    unsafe { f(&mut (*(&raw mut EXEC))[index].descriptors) }
}
pub fn shutting_down() -> bool {
    // SAFETY: this aligned scalar is published with interrupts disabled and copied on one hart.
    unsafe { SHUTDOWN }
}
pub fn set_shutdown() {
    let deadline = arch::now()
        .checked_add(crate::frequency() * 5)
        .unwrap_or_else(|| crate::fatal("SHUTDOWN_CLOCK"));
    let on = arch::disable();
    // SAFETY: publish the deadline and flag atomically against watchdog interrupts.
    // The flag is last so no observer can use an uninitialized shutdown deadline.
    unsafe {
        SHUTDOWN_DEADLINE = deadline;
        SHUTDOWN = true;
    }
    arch::restore(on);
    crate::diagnostics::event("shutdown", "SHUTDOWN_BEGIN", 257, deadline);
}
pub fn watchdog() {
    // SAFETY: SHUTDOWN publication guarantees the initialized deadline; this ISR only reads it.
    if shutting_down() && arch::now() >= unsafe { SHUTDOWN_DEADLINE } {
        crate::diagnostics::event("shutdown", "SHUTDOWN_UNCERTAIN", 257, unsafe {
            SHUTDOWN_DEADLINE
        });
        crate::log!("SHUTDOWN_UNCERTAIN\n");
        arch::shutdown();
    }
}
pub fn init() -> Result<(), Error> {
    // SAFETY: boot initializes the process table once before any process can run.
    unsafe {
        TABLE = Some(Table::new());
    }
    let init = table(|t| t.init());
    load(
        init,
        include_bytes!(env!("KERNEL_INIT_ELF")),
        &Arguments::new(),
    )?;
    descriptors_at(0, |d| {
        d.install(
            0,
            Descriptor {
                object: 1,
                readable: true,
                writable: false,
            },
        )?;
        d.install(
            1,
            Descriptor {
                object: 1,
                readable: false,
                writable: true,
            },
        )?;
        d.install(
            2,
            Descriptor {
                object: 1,
                readable: false,
                writable: true,
            },
        )
    })?;
    ready_push(init);
    Ok(())
}
fn load(pid: Pid, image: &[u8], args: &Arguments) -> Result<(), Error> {
    let mut plan = kernel_core::elf::LoadPlan::EMPTY;
    kernel_core::elf::validate_into(image, &mut plan)?;
    let index = pid.slot() - 1;
    let owner = pid.slot() as u16;
    let pages = plan.segments[..plan.count]
        .iter()
        .try_fold(16u64, |total, s| {
            total.checked_add((s.page_end - s.page_start) / 4096)
        })
        .ok_or(Error::NoMemory)?;
    if pages > 4096 {
        return Err(Error::NoMemory);
    }
    let root = memory::new_root(owner)?;
    let result = (|| {
        for segment in &plan.segments[..plan.count] {
            memory::allocate(
                root,
                owner,
                segment.page_start,
                (segment.page_end - segment.page_start) / 4096,
            )?;
            memory::copy_out(
                root,
                segment.address,
                &image[segment.offset..segment.offset + segment.file_size],
            )?;
            for va in (segment.page_start..segment.page_end).step_by(4096) {
                memory::protect(root, va, segment.flags & 1 != 0, segment.flags & 2 != 0)?;
            }
        }
        memory::allocate(root, owner, 0x40000000 - 65536, 16)?;
        let mut cursor = 0x40000000u64;
        let mut slices = [0u8; 256];
        for i in 0..args.count {
            let n = args.lengths[i];
            cursor -= n as u64 + 1;
            let input = &args.bytes[args.offsets[i]..args.offsets[i] + n];
            memory::copy_out(root, cursor, input)?; // zeroed stack supplies terminator
            slices[i * 16..i * 16 + 16].copy_from_slice(
                &kernel_abi::ArgSlice {
                    pointer: cursor,
                    length: n as u64,
                }
                .encode(),
            );
        }
        cursor &= !15;
        cursor -= args.count as u64 * 16;
        if args.count > 0 {
            memory::copy_out(root, cursor, &slices[..args.count * 16])?;
        }
        let top = memory::stack_top(index);
        let trap = (top - core::mem::size_of::<arch::Trap>() as u64) as *mut arch::Trap;
        // SAFETY: this slot has a mapped, private kernel stack and is not scheduled.
        unsafe {
            trap.write(arch::Trap::ZERO);
            (*trap).pc = plan.entry;
            (*trap).x[2] = (cursor - 16) & !15;
            (*trap).x[10] = args.count as u64;
            (*trap).x[11] = if args.count == 0 { 0 } else { cursor };
            // Reset fields in place: aggregate Execution temporaries overflow
            // the specified 16KiB process kernel stack in an unoptimized build.
            EXEC[index].context = arch::Context::ZERO;
            EXEC[index].descriptors = Descriptors::new();
            EXEC[index].extents.clear();
            EXEC[index].wait = None;
            EXEC[index].quantum = 0;
            EXEC[index].root = root;
            EXEC[index].pages = pages as u32;
            EXEC[index].context.0[0] = first_run as *const () as u64;
            EXEC[index].context.0[1] = trap as u64;
        }
        Ok(())
    })();
    if result.is_err() {
        memory::release(owner, root);
    }
    result
}
extern "C" fn first_run() -> ! {
    crate::metrics::switch_end();
    let trap = (memory::stack_top(current_index()) - core::mem::size_of::<arch::Trap>() as u64)
        as *mut arch::Trap;
    crate::metrics::user_enter(pid().raw());
    // The first sret bypasses rust_trap's normal interrupt-mask accounting exit.
    crate::metrics::irq_on();
    // SAFETY: load initialized the owned, aligned Trap on this process's live kernel stack.
    // enter_user restores only the validated user frame and never returns here.
    unsafe { arch::enter_user(trap) }
}
pub fn spawn(image: &[u8], args: &Arguments, stdio: [Option<Descriptor>; 3]) -> Result<Pid, Error> {
    let parent = pid();
    let child = table(|t| t.reserve(parent))?;
    if let Err(e) = load(child, image, args) {
        table(|t| t.abort(child)).unwrap_or_else(|_| crate::fatal("SPAWN_ROLLBACK"));
        return Err(e);
    }
    // Refcounts and descriptor publication cannot fail at the bounded 64*32 limit.
    for (fd, descriptor) in stdio.into_iter().enumerate() {
        if let Some(d) = descriptor {
            crate::syscall::retain(d).unwrap_or_else(|_| crate::fatal("DESCRIPTOR_RETAIN"));
            descriptors_at(child.slot() - 1, |table| table.install(fd, d))
                .unwrap_or_else(|_| crate::fatal("CHILD_DESCRIPTORS"));
        }
    }
    let on = arch::disable();
    table(|t| t.publish(child)).unwrap_or_else(|_| crate::fatal("SPAWN_PUBLICATION"));
    ready_push(child);
    arch::restore(on);
    Ok(child)
}
fn switch_out() {
    let index = current_index();
    crate::metrics::switch_begin();
    // SAFETY: interrupts are disabled; context pointers refer to distinct pinned static slots.
    // No Rust metadata reference survives the switch; the same stack resumes on return.
    unsafe {
        arch::switch_context(&raw mut EXEC[index].context, &raw const SCHEDULER);
    }
    crate::metrics::switch_end();
}
pub fn yield_now() {
    let on = arch::disable();
    let current = pid();
    table(|t| t.transition(current, State::Running, State::Ready))
        .unwrap_or_else(|_| crate::fatal("YIELD_STATE"));
    ready_push(current);
    switch_out();
    arch::restore(on);
}
pub fn block(reason: WaitReason) {
    let on = arch::disable();
    let current = pid();
    crate::trace::event(3, current.raw(), reason.code());
    // SAFETY: interrupts are disabled and current owns this slot until BLOCKED is published.
    unsafe {
        EXEC[current.slot() - 1].wait = Some(reason);
    }
    table(|t| t.transition(current, State::Running, State::Blocked))
        .unwrap_or_else(|_| crate::fatal("BLOCK_STATE"));
    crate::interleave::registered(reason.code());
    switch_out();
    arch::restore(on);
}
pub fn wake_all(reason: WaitReason) {
    let on = arch::disable();
    let mut wake = [None; 64];
    let mut count = 0;
    table(|t| {
        for p in t.published() {
            // SAFETY: published PIDs select live slots; this bounded scan cannot yield.
            if p.state == State::Blocked
                && let Some(id) = p.pid
                && unsafe { EXEC[id.slot() - 1].wait } == Some(reason)
            {
                wake[count] = Some(id);
                count += 1;
            }
        }
    });
    for id in wake[..count].iter().flatten().copied() {
        crate::interleave::waking(id.raw());
        crate::trace::event(4, id.raw(), reason.code());
        if let WaitReason::Sleep(deadline) = reason {
            crate::metrics::wake(id.raw(), deadline);
        }
        table(|t| t.transition(id, State::Blocked, State::Ready))
            .unwrap_or_else(|_| crate::fatal("WAKE_STATE"));
        // SAFETY: this published PID was transitioned atomically with interrupts disabled.
        unsafe {
            EXEC[id.slot() - 1].wait = None;
        }
        ready_push(id);
    }
    arch::restore(on);
}
pub fn io_progress() {
    // SAFETY: copied CURRENT distinguishes boot polling from a live process; no borrow survives.
    if unsafe { CURRENT }.is_some() {
        crate::interleave::io_before_check();
        let on = arch::disable();
        if !crate::drivers::virtio::completed() {
            block(WaitReason::Io);
        }
        arch::restore(on);
    } else {
        core::hint::spin_loop();
    }
}
pub fn sleep(ms: u64) -> Result<u64, Error> {
    if ms > 60000 {
        return Err(Error::Invalid);
    }
    if ms == 0 {
        yield_now();
        return Ok(0);
    }
    let deadline = kernel_core::scheduler::deadline(arch::now(), ms, crate::frequency())?;
    loop {
        let on = arch::disable();
        if arch::now() >= deadline {
            arch::restore(on);
            return Ok(0);
        }
        block(WaitReason::Sleep(deadline));
        arch::restore(on);
    }
}
pub fn page_alloc(pages: u64) -> Result<u64, Error> {
    let i = current_index();
    // SAFETY: this process exclusively owns its anonymous extents and this read cannot yield.
    let extent = unsafe { EXEC[i].extents.candidate(pages) }?;
    // SAFETY: only the current process changes its charged-page scalar.
    if unsafe { EXEC[i].pages } as u64 + pages > 4096 {
        return Err(Error::NoMemory);
    }
    memory::allocate(root(), pid().slot() as u16, extent.base, pages)?;
    // SAFETY: successful mapping commits only the current slot's previously checked extent.
    unsafe {
        EXEC[i]
            .extents
            .commit(extent)
            .unwrap_or_else(|_| crate::fatal("EXTENT_COMMIT"));
        EXEC[i].pages += pages as u32;
    }
    Ok(extent.base)
}
pub fn page_free(base: u64, pages: u64) -> Result<u64, Error> {
    let i = current_index();
    // SAFETY: current process owns this slot; exact-extent validation finishes before unmapping.
    unsafe { EXEC[i].extents.find(base, pages) }?;
    for n in 0..pages {
        memory::unmap(root(), pid().slot() as u16, base + n * 4096);
    }
    // SAFETY: all frames of the exact owned extent were unmapped; no peer can alter this ledger.
    unsafe {
        EXEC[i]
            .extents
            .remove(base, pages)
            .unwrap_or_else(|_| crate::fatal("EXTENT_REMOVE"));
        EXEC[i].pages -= pages as u32;
    }
    Ok(0)
}
pub fn wait(request: u64, out: u64, flags: u64) -> Result<u64, Error> {
    table(|t| t.wait_candidate(pid(), request))?;
    memory::validate(root(), out, 32, true)?;
    crate::interleave::before(2);
    loop {
        let on = arch::disable();
        let result = table(|t| t.wait_candidate(pid(), request));
        match result {
            Ok(Some(child)) => {
                let status = table(|t| t.get(child).ok().and_then(|p| p.status))
                    .unwrap_or_else(|| crate::fatal("ZOMBIE_STATUS"));
                let result = memory::copy_out(root(), out, &status.encode());
                if result.is_ok() {
                    table(|t| t.reap(pid(), child)).unwrap_or_else(|_| crate::fatal("REAP_STATE"));
                }
                arch::restore(on);
                result?;
                return Ok(child.raw());
            }
            Ok(None) => {
                if flags == 1 {
                    arch::restore(on);
                    return Err(Error::Again);
                }
                crate::interleave::checked(2);
                block(WaitReason::Child);
                arch::restore(on);
            }
            Err(e) => {
                arch::restore(on);
                return Err(e);
            }
        }
    }
}
pub fn exit(status: ExitRecord) -> ! {
    crate::trace::event(6, status.pid, u64::from(status.kind));
    if status.kind == 1 {
        crate::diagnostics::event("process", "USER_FAULT", status.pid, 0);
    }
    if pid() == table(|t| t.init()) {
        crate::fatal("INIT_EXIT");
    }
    let index = current_index();
    for fd in 0..32u64 {
        if let Ok(d) = with_descriptors(|table| table.close(fd)) {
            crate::syscall::release(d);
        }
    }
    let old_root = root();
    arch::activate(memory::kernel_root());
    // SAFETY: current process owns this execution slot; publish the kernel root before cleanup yields.
    unsafe {
        EXEC[index].root = memory::kernel_root();
    }
    memory::release(pid().slot() as u16, old_root);
    // SAFETY: release completed; clear only current ownership records before zombie publication.
    unsafe {
        EXEC[index].pages = 0;
        EXEC[index].extents.clear();
    }
    let _ = arch::disable();
    table(|t| t.finish_exit(pid(), status)).unwrap_or_else(|_| crate::fatal("EXIT_STATE"));
    wake_all(WaitReason::Child);
    switch_out();
    crate::fatal("EXIT_RETURNED")
}
pub fn snapshot(out: u64, capacity: usize) -> Result<u64, Error> {
    if capacity > 64 {
        return Err(Error::Invalid);
    }
    if capacity > 0 {
        memory::validate(root(), out, capacity * 32, true)?;
    }
    let mut records = [None; 64];
    let mut count = 0;
    table(|t| {
        for p in t.published() {
            records[count] = Some(*p);
            count += 1;
        }
    });
    if capacity < count {
        return Err(Error::BufferTooSmall);
    }
    records[..count].sort_unstable_by_key(|p| p.and_then(|p| p.pid));
    for (i, p) in records[..count].iter().flatten().enumerate() {
        let id = p.pid.unwrap_or_else(|| crate::fatal("PUBLISHED_PID"));
        let state = match p.state {
            State::Ready => 1,
            State::Running => 2,
            State::Blocked => 3,
            State::Zombie => 4,
            _ => crate::fatal("PUBLISHED_STATE"),
        };
        // SAFETY: snapshot and page counts are copied without scheduling; every PID is published.
        let bytes =
            kernel_abi::process_record(id.raw(), p.parent.map_or(0, Pid::raw), state, unsafe {
                EXEC[id.slot() - 1].pages
            })?;
        memory::copy_out(root(), out + i as u64 * 32, &bytes)?;
    }
    Ok(count as u64)
}
pub fn user_return() {
    crate::interleave::returning();
    crate::trace::event(5, pid().raw(), 0);
    if shutting_down() && pid() != table(|t| t.init()) {
        block(WaitReason::Shutdown);
    }
    // SAFETY: scheduler initialized the current slot's deadline before dispatch.
    if arch::now() >= unsafe { EXEC[current_index()].quantum } {
        yield_now();
    }
}
fn wake_events(now: u64) {
    crate::drivers::uart::service();
    if crate::drivers::uart::readable() {
        wake_all(WaitReason::ConsoleRead);
    }
    if crate::drivers::uart::writable() {
        wake_all(WaitReason::ConsoleWrite);
    }
    if crate::drivers::virtio::completed() {
        wake_all(WaitReason::Io);
    }
    let mut deadlines = [0u64; 64];
    let mut count = 0;
    table(|t| {
        for p in t.published() {
            // SAFETY: published PIDs select live slots; this bounded scan cannot yield.
            if p.state == State::Blocked
                && let Some(id) = p.pid
                && let Some(WaitReason::Sleep(d)) = unsafe { EXEC[id.slot() - 1].wait }
                && now >= d
            {
                deadlines[count] = d;
                count += 1;
            }
        }
    });
    for d in &deadlines[..count] {
        wake_all(WaitReason::Sleep(*d));
    }
    // SAFETY: scheduler alone reads/writes LAST_TIME while interrupts are disabled.
    // A timer wake also lets the device owner enforce its publication deadline.
    if now.saturating_sub(unsafe { LAST_TIME }) >= crate::frequency() / 1000 {
        wake_all(WaitReason::Io);
        // SAFETY: wake_events is scheduler-owned, interrupts remain disabled.
        unsafe {
            LAST_TIME = now;
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn scheduler_main() -> ! {
    loop {
        arch::disable();
        // SAFETY: scheduler owns the CPU here; no process can inspect CURRENT concurrently.
        unsafe {
            CURRENT = None;
        }
        if !arch::activate(memory::kernel_root()) {
            crate::fatal("SCHEDULER_SATP");
        }
        let now = arch::now();
        // SAFETY: LAST_TIME is a scheduler-owned scalar, copied under disabled interrupts.
        if now < unsafe { LAST_TIME } {
            crate::fatal("BACKWARDS_CLOCK");
        }
        wake_events(now);
        let mut zombies = [None; 64];
        let mut n = 0;
        table(|t| {
            for p in t.published() {
                if p.state == State::Zombie && p.auto_reap {
                    zombies[n] = p.pid;
                    n += 1;
                }
            }
        });
        for id in zombies[..n].iter().flatten() {
            table(|t| t.auto_reap(*id)).unwrap_or_else(|_| crate::fatal("AUTO_REAP"));
        }
        // SAFETY: disabled interrupts serialize the queue and this borrow ends before switching.
        let next = unsafe { (&mut *(&raw mut READY)).pop() };
        if let Some(raw) = next {
            let id = Pid::decode(raw).unwrap_or_else(|_| crate::fatal("READY_PID"));
            let i = id.slot() - 1;
            table(|t| t.transition(id, State::Ready, State::Running))
                .unwrap_or_else(|_| crate::fatal("DISPATCH_STATE"));
            // SAFETY: dequeued live PID owns this bounded slot; publish a fresh dispatch quantum.
            unsafe {
                CURRENT = Some(id);
                EXEC[i].quantum = kernel_core::scheduler::deadline(now, 5, crate::frequency())
                    .unwrap_or_else(|_| crate::fatal("QUANTUM_OVERFLOW"));
            }
            // SAFETY: load or exit cleanup installed a live root in this published slot.
            if !arch::activate(unsafe { EXEC[i].root }) {
                crate::fatal("USER_SATP");
            }
            crate::metrics::dispatch(id.raw());
            crate::trace::event(2, id.raw(), 0);
            // SAFETY: both context records are pinned, distinct and exclusively scheduler-owned.
            // All queue/table references ended before transferring to the owned process stack.
            unsafe {
                arch::switch_context(&raw mut SCHEDULER, &raw const EXEC[i].context);
            }
        } else {
            arch::enable();
            arch::wait();
        }
    }
}

pub fn cleanup_progress() {
    // SAFETY: copy CURRENT only; boot has no process stack to suspend.
    if unsafe { CURRENT }.is_some() {
        yield_now();
    }
}

#[cfg(feature = "instrumented")]
pub fn owner_counts() -> [u64; 4] {
    let published = table(|table| table.published().count() as u64);
    let mut descriptors = 0;
    let mut extents = 0;
    let mut pages = 0;
    // SAFETY: no scheduler transition occurs during this read-only owner census,
    // interrupts never access execution records, and no static reference escapes.
    for execution in unsafe { &*(&raw const EXEC) }.iter() {
        descriptors += (0..32)
            .filter(|fd| execution.descriptors.get(*fd).is_ok())
            .count() as u64;
        extents += execution.extents.iter().count() as u64;
        pages += u64::from(execution.pages);
    }
    [published, descriptors, extents, pages]
}
