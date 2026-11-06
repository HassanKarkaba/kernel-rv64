//! Copied syscall arguments, descriptor possession and serialized I/O ownership.
//! Kernel scratch is private to each occupied process, so suspension cannot
//! invalidate a validated user range or let another process replace input bytes.
use crate::{
    arch,
    drivers::{uart, virtio::Device},
    memory,
    process::{self, Arguments, WaitReason},
};

use kernel_abi::{self as abi, Error, OpenFlags, Syscall};
use kernel_core::{
    pipe::{Pipe, Transfer},
    process::Descriptor,
};
use kernel_fs::{Entry, FileSystem};

type Result<T> = core::result::Result<T, Error>;
const FILE_BASE: u32 = 2;
const PIPE_BASE: u32 = 258;
#[derive(Clone, Copy)]
struct OpenDescription {
    reserved: bool,
    references: u16,
    inode: u16,
    generation: u64,
    offset: u32,
}
impl OpenDescription {
    const EMPTY: Self = Self {
        reserved: false,
        references: 0,
        inode: 0,
        generation: 0,
        offset: 0,
    };
}
static mut OPEN: [OpenDescription; 256] = [OpenDescription::EMPTY; 256];
static mut PIPES: [Pipe; 64] = [const { Pipe::new() }; 64];
static mut PIPE_USED: [bool; 64] = [false; 64];
static mut SCRATCH: [[u8; 4096]; 64] = [[0; 4096]; 64];
static mut FS: *mut FileSystem<Device> = core::ptr::null_mut();
static mut FS_OWNER: Option<kernel_heap::Allocation<'static>> = None;
static mut MOUNTED: bool = false;
static mut SCAN: disk_format::ScanScratch = disk_format::ScanScratch::new();
static mut DIRECTORY: [Entry; 256] = [Entry::EMPTY; 256];
static mut LOADER: [u8; abi::MAX_EXEC_BYTES] = [0; abi::MAX_EXEC_BYTES];
static mut FS_BUSY: bool = false;
static mut LOADER_BUSY: bool = false;

struct Guard {
    loader: bool,
}
impl Guard {
    fn acquire(loader: bool) -> Self {
        loop {
            let on = arch::disable();
            // SAFETY: local interrupts serialize the predicate and waiter registration.
            let busy = unsafe { if loader { LOADER_BUSY } else { FS_BUSY } };
            if !busy {
                // SAFETY: interrupts remain disabled from the matching free-state check.
                unsafe {
                    if loader {
                        LOADER_BUSY = true;
                    } else {
                        FS_BUSY = true;
                    }
                }
                arch::restore(on);
                return Self { loader };
            }
            process::block(WaitReason::Fs);
            arch::restore(on);
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let on = arch::disable();
        // SAFETY: this guard is the only owner; no owner can be canceled asynchronously.
        unsafe {
            if self.loader {
                LOADER_BUSY = false;
            } else {
                FS_BUSY = false;
            }
        }
        process::wake_all(WaitReason::Fs);
        arch::restore(on);
    }
}
fn with_fs<R>(f: impl FnOnce(&mut FileSystem<Device>) -> Result<R>) -> Result<R> {
    let guard = Guard::acquire(false);
    if process::shutting_down() && process::pid().raw() != 257 {
        drop(guard);
        crate::interleave::shutdown_rejected();
        loop {
            process::block(WaitReason::Shutdown);
        }
    }
    // SAFETY: boot publishes MOUNTED once before user dispatch; it never changes later.
    if !unsafe { MOUNTED } {
        return Err(Error::Io);
    }
    // SAFETY: the sleepable guard exclusively owns FS through blocking driver calls.
    f(unsafe { &mut *FS })
}
fn fs_error(e: kernel_fs::Error) -> Error {
    match e {
        kernel_fs::Error::Invalid => Error::Invalid,
        kernel_fs::Error::NameTooLong => Error::NameTooLong,
        kernel_fs::Error::NotFound => Error::NotFound,
        kernel_fs::Error::Exists => Error::Exists,
        kernel_fs::Error::Busy => Error::Busy,
        kernel_fs::Error::NoSpace => Error::NoSpace,
        kernel_fs::Error::FileTooLarge => Error::FileTooBig,
        kernel_fs::Error::BufferTooSmall => Error::BufferTooSmall,
        kernel_fs::Error::ReadOnly => Error::ReadOnly,
        kernel_fs::Error::Io | kernel_fs::Error::Stale | kernel_fs::Error::Disk(_) => Error::Io,
    }
}
pub fn mount(device: Device) -> Result<()> {
    let mut allocation = memory::heap_allocate(
        core::mem::size_of::<FileSystem<Device>>(),
        core::mem::align_of::<FileSystem<Device>>(),
    )?;
    // SAFETY: boot exclusively owns this aligned heap allocation through FS_OWNER;
    // the filesystem guard later governs all access, including blocked device I/O.
    unsafe {
        FS = allocation.as_mut_ptr().cast::<FileSystem<Device>>();
        FS_OWNER = Some(allocation);
        FS.write(FileSystem::new(device));
        (&mut *FS).mount(&mut *(&raw mut SCAN)).map_err(fs_error)?;
        MOUNTED = true;
    }
    Ok(())
}
fn file_index(d: Descriptor) -> Option<usize> {
    if (FILE_BASE..PIPE_BASE).contains(&d.object) {
        Some((d.object - FILE_BASE) as usize)
    } else {
        None
    }
}
fn pipe_index(d: Descriptor) -> Option<(usize, bool)> {
    if (PIPE_BASE..PIPE_BASE + 128).contains(&d.object) {
        Some((
            ((d.object - PIPE_BASE) / 2) as usize,
            (d.object - PIPE_BASE) % 2 == 1,
        ))
    } else {
        None
    }
}
fn descriptor(fd: u64) -> Result<Descriptor> {
    process::with_descriptors(|d| d.get(fd))
}
fn open_description(index: usize) -> Result<OpenDescription> {
    // SAFETY: callers derive index from a checked descriptor; handlers never mutate OPEN.
    // This copies metadata and retains no reference across a scheduling point.
    let value = unsafe { OPEN[index] };
    if value.references == 0 || value.reserved {
        return Err(Error::BadDescriptor);
    }
    Ok(value)
}
fn is_open(inode: u16, generation: u64) -> bool {
    (0..256).any(|i| {
        // SAFETY: bounded index; filesystem guard and nonpreemptible S-mode protect this scan.
        let d = unsafe { OPEN[i] };
        d.references > 0 && d.inode == inode && d.generation == generation
    })
}
pub fn retain(d: Descriptor) -> Result<()> {
    let on = arch::disable();
    let result = (|| {
        if let Some(i) = file_index(d) {
            let value = open_description(i)?;
            // SAFETY: interrupts are disabled and descriptor possession pins this live entry.
            unsafe {
                OPEN[i].references = value
                    .references
                    .checked_add(1)
                    .ok_or(Error::FileTableFull)?;
            }
        } else if let Some((i, write)) = pipe_index(d) {
            // SAFETY: no scheduling occurs during endpoint reference changes.
            let p = unsafe {
                if !PIPE_USED[i] {
                    return Err(Error::BadDescriptor);
                }
                &mut (*(&raw mut PIPES))[i]
            };
            if write {
                p.add_writer()?;
            } else {
                p.add_reader()?;
            }
        } else if d.object > 1 {
            return Err(Error::BadDescriptor);
        }
        Ok(())
    })();
    arch::restore(on);
    result
}
pub fn release(d: Descriptor) {
    let on = arch::disable();
    if let Some(i) = file_index(d) {
        let old = open_description(i).unwrap_or_else(|_| crate::fatal("OPEN_RELEASE"));
        // SAFETY: disabled interrupts serialize the final reference and slot retirement.
        unsafe {
            OPEN[i].references = old.references - 1;
            if old.references == 1 {
                OPEN[i] = OpenDescription::EMPTY;
            }
        }
    } else if let Some((i, write)) = pipe_index(d) {
        let releasable = {
            // SAFETY: this descriptor pins the bounded pipe slot; no yield occurs in this borrow.
            let p = unsafe {
                if !PIPE_USED[i] {
                    crate::fatal("PIPE_RELEASE");
                }
                &mut (*(&raw mut PIPES))[i]
            };
            if write {
                p.close_writer()
                    .unwrap_or_else(|_| crate::fatal("PIPE_WRITERS"));
            } else {
                p.close_reader()
                    .unwrap_or_else(|_| crate::fatal("PIPE_READERS"));
            }
            p.releasable()
        };
        if releasable {
            // SAFETY: both endpoint counts are zero and the mutable borrow above has ended.
            unsafe {
                PIPE_USED[i] = false;
            }
        }
        process::wake_all(WaitReason::PipeRead(i));
        process::wake_all(WaitReason::PipeWrite(i));
    }
    arch::restore(on);
}

struct Path {
    bytes: [u8; 48],
    len: usize,
}
impl Path {
    fn name(&self) -> &[u8] {
        &self.bytes[1..self.len]
    }
}
fn path_length(length: u64) -> Result<usize> {
    if length > 48 {
        return Err(Error::NameTooLong);
    }
    if length < 2 {
        return Err(Error::Invalid);
    }
    Ok(length as usize)
}
fn path(pointer: u64, length: u64) -> Result<Path> {
    let len = path_length(length)?;
    let mut out = Path {
        bytes: [0; 48],
        len,
    };
    memory::copy_in(process::root(), pointer, &mut out.bytes[..len])?;
    abi::path_name(&out.bytes[..len])?;
    Ok(out)
}
fn scratch() -> &'static mut [u8; 4096] {
    // SAFETY: a process has one syscall and cannot mutate its scratch while blocked;
    // interrupts never access it and process cleanup waits for syscall completion.
    unsafe { &mut (*(&raw mut SCRATCH))[process::current_index()] }
}
fn open_file(a: &[u64; 6]) -> Result<u64> {
    let flags = OpenFlags::new(a[2])?;
    let path = path(a[0], a[1])?;
    let fd = process::with_descriptors(|d| d.free_slot())?;
    with_fs(|fs| {
        // Admission belongs to the same filesystem owner as lookup and mutation.
        // Even CREATE of an existing file and a write-capable open with no write
        // yet requested are forbidden after sequence exhaustion. Reject before
        // reserving an open description; malformed flags/paths were checked above.
        match fs.state() {
            kernel_fs::State::ReadOnly
                if flags.writable() || flags.create() || flags.truncate() =>
            {
                return Err(Error::ReadOnly);
            }
            kernel_fs::State::Healthy | kernel_fs::State::ReadOnly => {}
            _ => return Err(Error::Io),
        }
        let slot = (0..256)
            .find(|i| {
                // SAFETY: bounded scan cannot yield, and interrupt handlers do not touch OPEN.
                let o = unsafe { OPEN[*i] };
                o.references == 0 && !o.reserved
            })
            .ok_or(Error::FileTableFull)?;
        // SAFETY: reserve before any blocking filesystem work; other opens hold this same guard.
        unsafe {
            OPEN[slot].reserved = true;
        }
        let result = (|| {
            let mut stat = match fs.lookup(path.name()) {
                Ok(stat) => {
                    if flags.create() && flags.exclusive() {
                        return Err(Error::Exists);
                    }
                    stat
                }
                Err(kernel_fs::Error::NotFound) if flags.create() => {
                    fs.create(path.name()).map_err(fs_error)?
                }
                Err(e) => return Err(fs_error(e)),
            };
            if flags.truncate() {
                fs.truncate(stat.inode, stat.generation).map_err(fs_error)?;
                stat.size = 0;
                // SAFETY: the filesystem guard serializes offsets; this short update never yields.
                for description in unsafe { &mut *(&raw mut OPEN) }.iter_mut() {
                    if description.references > 0
                        && description.inode == stat.inode
                        && description.generation == stat.generation
                    {
                        description.offset = 0;
                    }
                }
            }
            // SAFETY: the reserved entry is unpublished and owned by this successful open.
            unsafe {
                OPEN[slot] = OpenDescription {
                    reserved: false,
                    references: 1,
                    inode: stat.inode,
                    generation: stat.generation,
                    offset: 0,
                };
            }
            let d = Descriptor {
                object: FILE_BASE + slot as u32,
                readable: flags.readable(),
                writable: flags.writable(),
            };
            process::with_descriptors(|table| table.install(fd, d))
                .unwrap_or_else(|_| crate::fatal("OPEN_PUBLICATION"));
            Ok(fd as u64)
        })();
        if result.is_err() {
            // SAFETY: a failed open never published its reserved slot or acquired any descriptor.
            unsafe {
                OPEN[slot] = OpenDescription::EMPTY;
            }
        }
        result
    })
}
fn close(fd: u64) -> Result<u64> {
    let d = process::with_descriptors(|table| table.close(fd))?;
    release(d);
    Ok(0)
}
fn duplicate(fd: u64) -> Result<u64> {
    let d = descriptor(fd)?;
    let slot = process::with_descriptors(|table| table.free_slot())?;
    retain(d)?;
    process::with_descriptors(|table| table.install(slot, d))
        .unwrap_or_else(|_| crate::fatal("DUP_PUBLICATION"));
    Ok(slot as u64)
}
fn pipe_create(pointer: u64) -> Result<u64> {
    memory::validate(process::root(), pointer, 8, true)?;
    let slots = process::with_descriptors(|table| table.two_free_slots())?;
    let on = arch::disable();
    let result = (|| {
        // SAFETY: disabled interrupts serialize bounded pipe allocation and publication.
        let slot = (0..64)
            .find(|i| unsafe { !PIPE_USED[*i] })
            .ok_or(Error::FileTableFull)?;
        // SAFETY: the selected free slot cannot be claimed while interrupts remain disabled.
        unsafe {
            PIPES[slot].reset();
            PIPE_USED[slot] = true;
        }
        process::with_descriptors(|table| {
            table.install(
                slots[0],
                Descriptor {
                    object: PIPE_BASE + slot as u32 * 2,
                    readable: true,
                    writable: false,
                },
            )?;
            table.install(
                slots[1],
                Descriptor {
                    object: PIPE_BASE + slot as u32 * 2 + 1,
                    readable: false,
                    writable: true,
                },
            )
        })
        .unwrap_or_else(|_| crate::fatal("PIPE_PUBLICATION"));
        memory::copy_out(
            process::root(),
            pointer,
            &abi::pipe_result(slots[0] as u32, slots[1] as u32),
        )
        .unwrap_or_else(|_| crate::fatal("PIPE_COPYOUT"));
        Ok(0)
    })();
    arch::restore(on);
    result
}
fn io(fd: u64, pointer: u64, length: u64, write: bool) -> Result<u64> {
    let d = descriptor(fd)?;
    if (write && !d.writable) || (!write && !d.readable) {
        return Err(Error::BadDescriptor);
    }
    if length > 4096 {
        return Err(Error::Invalid);
    }
    if length == 0 {
        return Ok(0);
    }
    let length = length as usize;
    let root = process::root();
    memory::validate(root, pointer, length, !write)?;
    let bytes = scratch();
    if write {
        memory::copy_in(root, pointer, &mut bytes[..length])?;
    }
    #[cfg(feature = "instrumented")]
    if write && d.object <= 1 {
        // Only this test build escapes user-console bytes. A bounded positive
        // prefix remains a legal console short write; it cannot forge KTEST.
        let n = length.min(512);
        crate::log!("UOUT {{\"pid\":{},\"data\":\"", process::pid().raw());
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in &bytes[..n] {
            match *byte {
                b'"' | b'\\' => {
                    uart::raw(b'\\');
                    uart::raw(*byte);
                }
                32..=126 => uart::raw(*byte),
                b => {
                    for c in b"\\u00" {
                        uart::raw(*c);
                    }
                    uart::raw(HEX[(b >> 4) as usize]);
                    uart::raw(HEX[(b & 15) as usize]);
                }
            }
        }
        crate::log!("\"}}\n");
        return Ok(n as u64);
    }
    if let Some(i) = file_index(d) {
        return with_fs(|fs| {
            let old = open_description(i)?;
            let n = if write {
                fs.write(old.inode, old.generation, old.offset, &bytes[..length])
                    .map_err(fs_error)?
            } else {
                fs.read(old.inode, old.generation, old.offset, &mut bytes[..length])
                    .map_err(fs_error)?
            };
            if !write {
                memory::copy_out(root, pointer, &bytes[..n])?;
            }
            // SAFETY: descriptor possession pins the entry; the filesystem guard owns its offset.
            unsafe {
                OPEN[i].offset = old.offset.checked_add(n as u32).ok_or(Error::Invalid)?;
            }
            Ok(n as u64)
        });
    }
    if !write && pipe_index(d).is_some() {
        crate::interleave::before(1);
    }
    loop {
        let on = arch::disable();
        let outcome: Result<Transfer> = if let Some((i, endpoint_write)) = pipe_index(d) {
            if write != endpoint_write {
                arch::restore(on);
                return Err(Error::BadDescriptor);
            }
            let result = {
                // SAFETY: the descriptor pins this pipe and interrupts are disabled.
                // The borrow ends before wakeup processing or any blocking context switch.
                let pipe = unsafe {
                    if !PIPE_USED[i] {
                        crate::fatal("PIPE_IO_OWNER");
                    }
                    &mut (*(&raw mut PIPES))[i]
                };
                if write {
                    pipe.try_write(process::pid().raw(), &bytes[..length])
                } else {
                    pipe.try_read(process::pid().raw(), &mut bytes[..length])
                }
            };
            if matches!(result, Ok(Transfer::Complete(_))) {
                process::wake_all(WaitReason::PipeRead(i));
                process::wake_all(WaitReason::PipeWrite(i));
            }
            result
        } else if d.object <= 1 {
            let n = if write {
                uart::transmit(&bytes[..length])
            } else {
                uart::receive(&mut bytes[..length])
            };
            Ok(if n == 0 {
                Transfer::Blocked
            } else {
                Transfer::Complete(n)
            })
        } else {
            Err(Error::BadDescriptor)
        };
        match outcome {
            Ok(Transfer::Complete(n)) => {
                arch::restore(on);
                if !write {
                    memory::copy_out(root, pointer, &bytes[..n])?;
                }
                return Ok(n as u64);
            }
            Ok(Transfer::Blocked) => {
                if !write && pipe_index(d).is_some() {
                    crate::interleave::checked(1);
                }
                let reason = if let Some((i, _)) = pipe_index(d) {
                    if write {
                        WaitReason::PipeWrite(i)
                    } else {
                        WaitReason::PipeRead(i)
                    }
                } else if write {
                    WaitReason::ConsoleWrite
                } else {
                    WaitReason::ConsoleRead
                };
                process::block(reason);
                arch::restore(on);
            }
            Err(error) => {
                arch::restore(on);
                return Err(error);
            }
        }
    }
}
fn seek(fd: u64, offset: u64) -> Result<u64> {
    let d = descriptor(fd)?;
    let index = file_index(d).ok_or(Error::IllegalSeek)?;
    with_fs(|fs| {
        let old = open_description(index)?;
        let stat = fs.stat(old.inode, old.generation).map_err(fs_error)?;
        if offset > u64::from(stat.size) {
            return Err(Error::Invalid);
        }
        // SAFETY: a live descriptor pins this entry and the filesystem guard owns its offset.
        unsafe {
            OPEN[index].offset = offset as u32;
        }
        Ok(offset)
    })
}
fn fsync(fd: u64) -> Result<u64> {
    let d = descriptor(fd)?;
    let i = file_index(d).ok_or(Error::Invalid)?;
    open_description(i)?;
    with_fs(|fs| {
        fs.fsync().map_err(fs_error)?;
        Ok(0)
    })
}
fn stat(a: &[u64; 6]) -> Result<u64> {
    let path = path(a[0], a[1])?;
    memory::validate(process::root(), a[2], 32, true)?;
    with_fs(|fs| {
        let stat = fs.lookup(path.name()).map_err(fs_error)?;
        memory::copy_out(
            process::root(),
            a[2],
            &abi::file_stat(stat.inode as u32, stat.generation, stat.size as u64),
        )?;
        Ok(0)
    })
}
fn list(pointer: u64, capacity: usize) -> Result<u64> {
    if capacity > 256 {
        return Err(Error::Invalid);
    }
    if capacity > 0 {
        memory::validate(process::root(), pointer, capacity * 64, true)?;
    }
    with_fs(|fs| {
        // SAFETY: the filesystem mutex owns this shared snapshot through copyout.
        let records = unsafe { &mut *(&raw mut DIRECTORY) };
        let n = fs.list(&mut records[..capacity]).map_err(fs_error)?;
        for (i, record) in records[..n].iter().enumerate() {
            let bytes = abi::directory_record(
                record.stat.inode as u32,
                record.stat.size as u64,
                &record.name[..record.name_len as usize],
            )?;
            memory::copy_out(process::root(), pointer + i as u64 * 64, &bytes)?;
        }
        Ok(n as u64)
    })
}
fn spawn(a: &[u64; 6]) -> Result<u64> {
    let path = path(a[0], a[1])?;
    let count = a[3] as usize;
    let mut records = [0u8; 256];
    if count > 0 {
        memory::copy_in(process::root(), a[2], &mut records[..count * 16])?;
    }
    let mut args = Arguments::new();
    args.count = count;
    let mut total = 0;
    for i in 0..count {
        let wire: [u8; 16] = records[i * 16..i * 16 + 16]
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let arg = abi::ArgSlice::decode(&wire);
        if arg.length > 255 {
            return Err(Error::TooBig);
        }
        let n = arg.length as usize;
        if total + n + 1 > 1024 {
            return Err(Error::TooBig);
        }
        args.offsets[i] = total;
        args.lengths[i] = n;
        total += n + 1;
    }
    for i in 0..count {
        let wire: [u8; 16] = records[i * 16..i * 16 + 16]
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let arg = abi::ArgSlice::decode(&wire);
        let start = args.offsets[i];
        let end = start + args.lengths[i];
        memory::copy_in(process::root(), arg.pointer, &mut args.bytes[start..end])?;
        if args.bytes[start..end].contains(&0) {
            return Err(Error::Invalid);
        }
    }
    let mut stdio = [0u8; 12];
    memory::copy_in(process::root(), a[4], &mut stdio)?;
    let map = abi::decode_stdio(&stdio)?;
    let inherited = process::with_descriptors(|d| d.stdio_snapshot(map))?;
    let _loader = Guard::acquire(true);
    let length = with_fs(|fs| {
        let stat = fs.lookup(path.name()).map_err(fs_error)?;
        let length = stat.size as usize;
        if length > abi::MAX_EXEC_BYTES {
            return Err(Error::TooBig);
        }
        // SAFETY: loader guard owns this bounded buffer through all blocking file reads.
        let image = unsafe { &mut *(&raw mut LOADER) };
        let mut offset = 0;
        while offset < length {
            let end = (offset + 4096).min(length);
            let n = fs
                .read(
                    stat.inode,
                    stat.generation,
                    offset as u32,
                    &mut image[offset..end],
                )
                .map_err(fs_error)?;
            if n != end - offset {
                return Err(Error::Io);
            }
            offset = end;
        }
        Ok(length)
    })?;
    // SAFETY: loader guard retains the initialized immutable snapshot after releasing FS.
    // It remains held until process::spawn has copied all load segments.
    let image = unsafe { &(&*(&raw const LOADER))[..length] };
    process::spawn(image, &args, inherited).map(|pid| pid.raw())
}
fn shutdown() -> Result<u64> {
    if process::pid().raw() != 257 {
        return Err(Error::Permission);
    }
    process::set_shutdown();
    crate::interleave::shutdown_wait();
    let deadline = arch::now()
        .checked_add(crate::frequency().checked_mul(5).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?;
    loop {
        let on = arch::disable();
        // SAFETY: disabled interrupts serialize the final filesystem ownership handoff.
        if !unsafe { FS_BUSY } {
            // SAFETY: the free-state check above and acquisition form one masked critical section.
            unsafe {
                FS_BUSY = true;
            }
            arch::restore(on);
            break;
        }
        arch::restore(on);
        if arch::now() >= deadline {
            crate::diagnostics::event("shutdown", "SHUTDOWN_UNCERTAIN", 257, 0);
            crate::log!("SHUTDOWN_UNCERTAIN\n");
            arch::shutdown();
        }
        process::yield_now();
    }
    // SAFETY: shutdown owns the mutex permanently; boot initialized FS and no new owner is admitted.
    let result = unsafe { &mut *FS }.flush();
    if result.is_ok() && arch::now() < deadline {
        crate::diagnostics::event("shutdown", "SHUTDOWN_CLEAN", 257, 0);
        crate::log!("SHUTDOWN_CLEAN\n");
    } else {
        crate::diagnostics::event("shutdown", "SHUTDOWN_UNCERTAIN", 257, 0);
        crate::log!("SHUTDOWN_UNCERTAIN\n");
    }
    arch::shutdown()
}

pub fn dispatch(frame: &arch::Trap) -> i64 {
    let number = frame.x[17];
    let args: [u64; 6] = frame.x[10..16]
        .try_into()
        .unwrap_or_else(|_| crate::fatal("SYSCALL_REGISTERS"));
    let result = (|| {
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_4652 {
            if args[1..].iter().any(|value| *value != 0) || !matches!(args[0], 1 | 2) {
                return Err(Error::Invalid);
            }
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            // SAFETY: this declared test deliberately causes a nonreturning S-mode
            // fault; it exports no reference and must terminate on the emergency stack.
            unsafe {
                if args[0] == 1 {
                    core::arch::asm!("ld zero, 0(zero)", options(noreturn));
                }
                let guard = memory::STACKS + process::current_index() as u64 * 20480;
                core::arch::asm!("mv sp, {guard}", "sd zero, 0(sp)", guard=in(reg)guard, options(noreturn));
            }
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_494c {
            if args[2..].iter().any(|value| *value != 0) {
                return Err(Error::Invalid);
            }
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            return crate::interleave::control(args[0], args[1]);
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_5243 {
            if args[4..].iter().any(|value| *value != 0) {
                return Err(Error::Invalid);
            }
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            return crate::trace::control(args[0], args[1], args[2], args[3]);
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_4649 {
            if args[1..].iter().any(|v| *v != 0) {
                return Err(Error::Invalid);
            }
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            crate::drivers::virtio::inject_next(args[0])?;
            return Ok(0);
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_4d45 {
            if args[4..].iter().any(|value| *value != 0) {
                return Err(Error::Invalid);
            }
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            match args[0] {
                0 => {
                    if !matches!(args[2], 4 | 8) || args[3] != 0 {
                        return Err(Error::Invalid);
                    }
                    let count = args[2] as usize;
                    let mut wire = [0u8; 64];
                    let mut pids = [0u64; 8];
                    memory::copy_in(process::root(), args[1], &mut wire[..count * 8])?;
                    for (i, pid) in pids[..count].iter_mut().enumerate() {
                        *pid = u64::from_le_bytes(
                            wire[i * 8..i * 8 + 8]
                                .try_into()
                                .map_err(|_| Error::Invalid)?,
                        );
                    }
                    crate::metrics::reset(&pids[..count])?;
                    return Ok(0);
                }
                1 => {
                    if args[2] != 416 || args[3] != 0 {
                        return Err(Error::Invalid);
                    }
                    memory::validate(process::root(), args[1], 416, true)?;
                    let (bytes, n) = crate::metrics::snapshot();
                    memory::copy_out(process::root(), args[1], &bytes)?;
                    return Ok(n as u64);
                }
                2 => {
                    if args[2] > 256 {
                        return Err(Error::Invalid);
                    }
                    let size = args[2] as usize * 16;
                    memory::validate(process::root(), args[1], size, true)?;
                    let out = scratch();
                    let n = crate::metrics::trace(args[3] as usize, &mut out[..size])?;
                    memory::copy_out(process::root(), args[1], &out[..n * 16])?;
                    return Ok(n as u64);
                }
                _ => return crate::metrics::control(args[0], args[1], args[2], args[3]),
            }
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_5541 {
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            if args[1] != 16 || args[2..].iter().any(|value| *value != 0) {
                return Err(Error::Invalid);
            }
            memory::copy_out(process::root(), args[0], &uart::test_counters())?;
            return Ok(0);
        }
        #[cfg(feature = "instrumented")]
        if number == 0x4b54_4553 {
            if process::pid().raw() != 257 {
                return Err(Error::Permission);
            }
            if args[2..].iter().any(|value| *value != 0) || args[1] > 512 {
                uart::fail_test_output();
                return Err(Error::Invalid);
            }
            let bytes = scratch();
            if let Err(error) =
                memory::copy_in(process::root(), args[0], &mut bytes[..args[1] as usize])
            {
                uart::fail_test_output();
                return Err(error);
            }
            uart::test_record(&bytes[..args[1] as usize])?;
            return Ok(0);
        }
        let call = Syscall::decode(number)?;
        if args[call.argument_count()..]
            .iter()
            .any(|value| *value != 0)
        {
            return Err(Error::Invalid);
        }
        // All path length scalars precede pointer dereferences, including rename's second path.
        match call {
            Syscall::Spawn | Syscall::Open | Syscall::Stat | Syscall::Unlink => {
                path_length(args[1])?;
            }
            Syscall::Rename => {
                path_length(args[1])?;
                path_length(args[3])?;
            }
            _ => {}
        }
        call.validate_scalars(&args)?;
        if process::shutting_down() && process::pid().raw() != 257 {
            loop {
                process::block(WaitReason::Shutdown);
            }
        }
        match call {
            Syscall::AbiInfo => {
                memory::copy_out(process::root(), args[0], &abi::abi_info())?;
                Ok(0)
            }
            Syscall::Exit => process::exit(abi::ExitRecord::normal(process::pid().raw(), args[0])),
            Syscall::GetPid => Ok(process::pid().raw()),
            Syscall::Yield => {
                process::yield_now();
                Ok(0)
            }
            Syscall::Sleep => process::sleep(args[0]),
            Syscall::Clock => kernel_core::scheduler::nanoseconds(arch::now(), crate::frequency())
                .map(|n| n as u64),
            Syscall::PageAlloc => process::page_alloc(args[0]),
            Syscall::PageFree => process::page_free(args[0], args[1]),
            Syscall::Spawn => spawn(&args),
            Syscall::Wait => process::wait(args[0], args[1], args[2]),
            Syscall::Open => open_file(&args),
            Syscall::Close => close(args[0]),
            Syscall::Read => io(args[0], args[1], args[2], false),
            Syscall::Write => io(args[0], args[1], args[2], true),
            Syscall::Seek => seek(args[0], args[1]),
            Syscall::Fsync => fsync(args[0]),
            Syscall::Stat => stat(&args),
            Syscall::List => list(args[0], args[1] as usize),
            Syscall::Unlink => {
                let name = path(args[0], args[1])?;
                with_fs(|fs| {
                    fs.unlink(name.name(), is_open).map_err(fs_error)?;
                    Ok(0)
                })
            }
            Syscall::Rename => {
                let old = path(args[0], args[1])?;
                let new = path(args[2], args[3])?;
                with_fs(|fs| {
                    fs.rename(old.name(), new.name(), is_open)
                        .map_err(fs_error)?;
                    Ok(0)
                })
            }
            Syscall::Pipe => pipe_create(args[0]),
            Syscall::Dup => duplicate(args[0]),
            Syscall::ProcessList => process::snapshot(args[0], args[1] as usize),
            Syscall::Shutdown => shutdown(),
        }
    })();
    match result {
        Ok(value) => value as i64,
        Err(error) => error.return_value(),
    }
}

#[cfg(feature = "instrumented")]
pub fn owner_counts() -> [u64; 5] {
    // SAFETY: this bounded census never yields, interrupts never mutate these objects,
    // and ordinary S-mode cannot be preempted into another owner's descriptor mutation.
    let mut counts = [0u64; 5];
    unsafe {
        for description in &*(&raw const OPEN) {
            counts[0] += u64::from(description.references != 0 || description.reserved);
            counts[1] += u64::from(description.references);
        }
        for (i, pipe) in (&*(&raw const PIPES)).iter().enumerate() {
            if !PIPE_USED[i] {
                continue;
            }
            counts[2] += 1;
            counts[3] += u64::from(pipe.readers());
            counts[4] += u64::from(pipe.writers());
        }
    }
    counts
}
