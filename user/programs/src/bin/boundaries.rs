#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn raw(n: u64, a: [u64; 6]) -> i64 {
    unsafe { rt::raw(n, a) }
}
fn check(ok: bool, id: u32) -> Result<(), u32> {
    if ok { Ok(()) } else { Err(id) }
}
fn child(mode: &[u8]) -> Result<u64, u32> {
    rt::spawn(b"/fault-probe", &[mode], [-1, -1, -1]).map_err(|_| 1000)
}
fn work() -> Result<(), u32> {
    // Each syscall rejects nonzero unused registers before following any pointer.
    for n in 0..24 {
        let mut a = [0; 6];
        a[5] = 1;
        check(raw(n, a) == -22, 100 + n as u32)?;
    }
    for n in [24, 255, 0x4b544553, 0x4b544d45, 0x4b545243, 0x4b544649] {
        check(raw(n, [0; 6]) < 0, 125)?;
    }
    for mode in [
        b"null".as_slice(),
        b"text",
        b"kernel",
        b"guard",
        b"csr",
        b"sfence",
        b"execute",
        b"freed",
    ] {
        let pid = child(mode)?;
        let status = rt::wait(pid, false).map_err(|_| 130u32)?;
        check(status.kind == 1, 131)?;
        if mode == b"kernel" || mode == b"null" {
            check(status.fault_address == 0, 132)?;
        }
        if mode == b"text" {
            check(status.cause == 15, 133)?;
        }
        if mode == b"execute" {
            check(status.cause == 12, 134)?;
        }
        if mode == b"csr" || mode == b"sfence" {
            check(status.cause == 2, 135)?;
        }
    }
    let pid = child(b"badsp")?;
    let status = rt::wait(pid, false).map_err(|_| 136u32)?;
    check(status.kind == 0 && status.code == 0, 137)?;
    let page = rt::page_alloc(1).map_err(|_| 140u32)?;
    unsafe {
        core::ptr::write_volatile(page as *mut u64, 0xaa);
    }
    let peer = child(b"private")?;
    let status = rt::wait(peer, false).map_err(|_| 141u32)?;
    check(
        status.kind == 0
            && status.code == 0
            && unsafe { core::ptr::read_volatile(page as *const u64) } == 0xaa,
        142,
    )?;
    unsafe { rt::page_free(page, 1) }.map_err(|_| 143u32)?;
    // Extent-table exhaustion must roll back and leave all existing allocations freeable.
    let mut extents = [0u64; 256];
    for e in &mut extents {
        *e = rt::page_alloc(1).map_err(|_| 144u32)?;
    }
    check(rt::page_alloc(1) == Err(-12), 145)?;
    for e in extents {
        unsafe { rt::page_free(e, 1) }.map_err(|_| 146u32)?;
    }
    let mut quota = [0u64; 16];
    let mut n = 0;
    loop {
        match rt::page_alloc(256) {
            Ok(p) => {
                if n == 16 {
                    return Err(147);
                }
                quota[n] = p;
                n += 1;
            }
            Err(-12) => break,
            _ => return Err(148),
        }
    }
    check((14..=15).contains(&n), 149)?;
    for p in &quota[..n] {
        unsafe { rt::page_free(*p, 256) }.map_err(|_| 150u32)?;
    }
    let again = rt::page_alloc(1).map_err(|_| 151u32)?;
    unsafe { rt::page_free(again, 1) }.map_err(|_| 152u32)?;
    // Per-process fd exhaustion, no leaked half-pipe, and retained descriptor rights.
    let mut fds = [0u32; 32];
    let mut count = 0;
    while let Ok(fd) = rt::dup(1) {
        if count == 32 {
            return Err(160);
        }
        fds[count] = fd;
        count += 1;
    }
    check(raw(21, [1, 0, 0, 0, 0, 0]) == -24, 161)?;
    check(rt::pipe() == Err(-24), 162)?;
    for fd in &fds[..count] {
        rt::close(*fd).map_err(|_| 163u32)?;
    }
    let pipe = rt::pipe().map_err(|_| 164u32)?;
    check(rt::write(pipe[0], b"x") == Err(-9), 165)?;
    let mut b = [0u8; 8];
    check(rt::read(pipe[1], &mut b) == Err(-9), 166)?;
    check(
        rt::seek(pipe[0], 0) == Err(-29) && rt::fsync(pipe[0]) == Err(-22),
        167,
    )?;
    rt::close(pipe[1]).map_err(|_| 168u32)?;
    check(rt::read(pipe[0], &mut b) == Ok(0), 169)?;
    rt::close(pipe[0]).map_err(|_| 170u32)?;
    // Parent-only wait, NOHANG, stale PID, and lowest-PID any-child selection.
    let mut children = [0u64; 3];
    for pid in &mut children {
        *pid = child(b"sleep")?;
    }
    check(
        rt::wait(rt::getpid().map_err(|_| 180u32)?, true) == Err(-10),
        181,
    )?;
    rt::sleep(60).map_err(|_| 182u32)?;
    children.sort_unstable();
    for expected in children {
        let result = rt::wait(0, false).map_err(|_| 183u32)?;
        check(result.pid == expected && result.kind == 0, 184)?;
    }
    let newer = child(b"exit")?;
    check(!children.contains(&newer), 185)?;
    check(rt::wait(children[0], true) == Err(-10), 186)?;
    rt::wait(newer, false).map_err(|_| 187u32)?;
    // Fill occupied process slots (zombies still occupy slots) then recover admission.
    let mut pids = [0u64; 63];
    let mut count = 0;
    loop {
        match rt::spawn(b"/fault-probe", &[b"exit"], [-1, -1, -1]) {
            Ok(pid) => {
                if count == 63 {
                    return Err(190);
                }
                pids[count] = pid;
                count += 1;
            }
            Err(-11) => break,
            _ => return Err(191),
        }
    }
    check(count == 62, 192)?;
    for pid in &pids[..count] {
        rt::wait(*pid, false).map_err(|_| 193u32)?;
    }
    let again = child(b"exit")?;
    rt::wait(again, false).map_err(|_| 194u32)?;
    // Namespace/scalar rejections never create or truncate a target.
    for bad in [
        b"".as_slice(),
        b"/",
        b"/.",
        b"/..",
        b"/a/b",
        b"/a\0b",
        b"relative",
    ] {
        check(rt::open(bad, 3 | 0x100) == Err(-22), 200)?;
    }
    check(rt::open(&[b'x'; 49], 1) == Err(-36), 201)?;
    for flags in [0, 4, 1 | 0x200, 1 | 0x400, 3 | 0x800] {
        check(rt::open(b"/invalid", flags) == Err(-22), 202)?;
    }
    check(rt::stat(b"/invalid") == Err(-2), 203)?;
    check(raw(17, [u64::MAX, 257, 0, 0, 0, 0]) == -22, 204)?;
    check(raw(22, [u64::MAX, 65, 0, 0, 0, 0]) == -22, 205)?;
    check(raw(17, [u64::MAX, 0, 0, 0, 0, 0]) == -105, 206)?;
    check(raw(22, [u64::MAX, 0, 0, 0, 0, 0]) == -105, 207)?;
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    match work() {
        Ok(()) => {
            rt::println!("boundary matrix passed");
            0
        }
        Err(id) => {
            rt::println!("boundary matrix failed assertion={}", id);
            1
        }
    }
}
