#![no_std]
#![no_main]
use core::fmt::{self, Write};
use user_runtime as rt;
rt::entry!(main);
struct Json {
    bytes: [u8; 512],
    len: usize,
}
impl Write for Json {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.len + s.len() > 512 {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
        self.len += s.len();
        Ok(())
    }
}
fn emit(sequence: u64, event: &str, fields: fmt::Arguments<'_>) {
    let mut json = Json {
        bytes: [0; 512],
        len: 0,
    };
    let case = "abi-matrix";
    write!(&mut json,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"event\":\"{}\",\"case_id\":\"{}\",\"sequence\":{}",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),event,case,sequence).unwrap();
    json.write_fmt(fields).unwrap();
    json.write_str("}").unwrap();
    // SAFETY: the immutable supervisor owns this initialized JSON buffer.
    if unsafe {
        rt::raw(
            0x4b544553,
            [json.bytes.as_ptr() as u64, json.len as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        rt::exit(127);
    }
}
fn raw(n: u64, a: [u64; 6]) -> i64 {
    unsafe { rt::raw(n, a) }
}
fn check(seq: &mut u64, id: &str, observed: i64, expected: i64) -> rt::Result<()> {
    *seq += 1;
    emit(
        *seq,
        "assertion",
        format_args!(
            ",\"assertion\":\"{}\",\"observed\":{},\"expected\":{},\"result\":\"{}\"",
            id,
            observed,
            expected,
            if observed == expected { "PASS" } else { "FAIL" }
        ),
    );
    if observed == expected {
        Ok(())
    } else {
        Err(-5)
    }
}
fn check_call(seq: &mut u64, id: &str, call: u64, args: [u64; 6], expected: i64) -> rt::Result<()> {
    let observed = raw(call, args);
    *seq += 1;
    emit(
        *seq,
        "assertion",
        format_args!(
            ",\"assertion\":\"{}\",\"call\":{},\"args\":[{},{},{},{},{},{}],\"observed\":{},\"expected\":{},\"result\":\"{}\"",
            id,
            call,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            observed,
            expected,
            if observed == expected { "PASS" } else { "FAIL" }
        ),
    );
    if observed == expected {
        Ok(())
    } else {
        Err(-5)
    }
}
fn condition(seq: &mut u64, id: &str, good: bool) -> rt::Result<()> {
    check(seq, id, i64::from(good), 1)
}
fn census() -> rt::Result<[u8; 128]> {
    let mut out = [0u8; 128];
    let n = raw(0x4b544d45, [9, out.as_mut_ptr() as u64, 128, 0, 0, 0]);
    if n == 128 { Ok(out) } else { Err(n) }
}
fn child(args: &[&[u8]]) -> rt::Result<rt::abi::ExitRecord> {
    let pid = rt::spawn(b"/abi-matrix-worker", args, [-1, -1, -1])?;
    rt::wait(pid, false)
}
fn work(seq: &mut u64) -> rt::Result<()> {
    let initial = census()?;
    for n in 0..24 {
        let mut args = [0; 6];
        args[5] = 1;
        check_call(seq, "unused-register", n, args, -22)?;
    }
    for n in [24, 255, u64::MAX] {
        check(seq, "unknown-number", raw(n, [0; 6]), -38)?;
    }
    condition(seq, "getpid-valid", rt::getpid()? == 257)?;
    check(seq, "yield-valid", raw(3, [0; 6]), 0)?;
    check(seq, "sleep-zero", raw(4, [0; 6]), 0)?;
    let time = rt::clock()?;
    rt::sleep(1)?;
    condition(
        seq,
        "sleep-positive-no-round-down",
        rt::clock()? >= time + 1_000_000,
    )?;
    let time = rt::clock()?;
    rt::sleep(60000)?;
    condition(seq, "sleep-max", rt::clock()? >= time + 60_000_000_000)?;
    for n in [60001, u64::MAX] {
        check(seq, "sleep-invalid-scalar", raw(4, [n, 0, 0, 0, 0, 0]), -22)?;
    }
    condition(seq, "exit-min", child(&[])?.code == 0)?;
    condition(
        seq,
        "exit-low32-max",
        child(&[b"exit-max"])?.code == u32::MAX,
    )?;
    condition(seq, "child-authority", child(&[b"authority"])?.code == 0)?;
    let max_arg = [b'x'; 63];
    let args = [max_arg.as_slice(); 16];
    condition(seq, "spawn-max-argv", child(&args)?.code == 0)?;
    let huge = rt::page_alloc(256)?;
    unsafe { rt::page_free(huge, 256) }?;
    for n in [0, 257, u64::MAX] {
        check(seq, "alloc-invalid-scalar", raw(6, [n, 0, 0, 0, 0, 0]), -22)?;
    }
    let page = rt::page_alloc(1)?;
    unsafe {
        core::ptr::write_bytes(page as *mut u8, 0x5a, 4096);
    }
    for (base, n) in [
        (page, 0),
        (page, 257),
        (page + 1, 1),
        (page + 4096, 1),
        (u64::MAX, 1),
    ] {
        check(
            seq,
            "free-invalid-no-effect",
            raw(7, [base, n, 0, 0, 0, 0]),
            -22,
        )?;
        condition(
            seq,
            "free-data-preserved",
            unsafe { core::ptr::read_volatile(page as *const u8) } == 0x5a,
        )?;
    }
    unsafe { rt::page_free(page, 1) }?;
    check(seq, "free-double", raw(7, [page, 1, 0, 0, 0, 0]), -22)?;
    let page = rt::page_alloc(1)?;
    condition(
        seq,
        "reuse-zero",
        unsafe { core::slice::from_raw_parts(page as *const u8, 4096) }
            .iter()
            .all(|v| *v == 0),
    )?;
    unsafe {
        core::ptr::write_volatile((page + 4095) as *mut u8, b'/');
    }
    let name = b"/matrix";
    let path = name.as_ptr() as u64;
    let fd = rt::open(name, 3 | 0x100 | 0x200)?;
    let data = [0x39u8; 4096];
    condition(seq, "write-max", rt::write(fd, &data)? == 4096)?;
    let read_only = rt::open(name, 1)?;
    let write_only = rt::open(name, 2)?;
    let readonly_name = b"/abi-matrix-worker";
    let exec = readonly_name.as_ptr() as u64;
    let stdio = [-1i32; 3];
    let stdio_ptr = stdio.as_ptr() as u64;
    let pipe = rt::pipe()?;
    rt::write(pipe[1], b"safe")?;
    let owners = census()?;
    // The entire rejection matrix below runs with trace collection active.
    // A separate oracle requires zero block submissions before collection stops.
    check(seq, "trace-start", raw(0x4b545243, [0; 6]), 0)?;
    for pointer in [0, 0x18000000, page + 4095, u64::MAX - 1] {
        for (n, a) in [
            (0, [pointer, 0, 0, 0, 0, 0]),
            (8, [pointer, 2, 0, 0, stdio_ptr, 0]),
            (8, [exec, 18, pointer, 1, stdio_ptr, 0]),
            (8, [exec, 18, 0, 0, pointer, 0]),
            (10, [pointer, 2, 1, 0, 0, 0]),
            (12, [fd as u64, pointer, 2, 0, 0, 0]),
            (13, [fd as u64, pointer, 2, 0, 0, 0]),
            (16, [pointer, 2, page, 0, 0, 0]),
            (16, [path, 7, pointer, 0, 0, 0]),
            (17, [pointer, 256, 0, 0, 0, 0]),
            (18, [pointer, 2, 0, 0, 0, 0]),
            (19, [pointer, 2, path, 7, 0, 0]),
            (19, [path, 7, pointer, 2, 0, 0]),
            (20, [pointer, 0, 0, 0, 0, 0]),
            (22, [pointer, 64, 0, 0, 0, 0]),
        ] {
            check_call(seq, "pointer-complete-range", n, a, -14)?;
        }
        check(
            seq,
            "pipe-read-no-consume",
            raw(12, [pipe[0] as u64, pointer, 8, 0, 0, 0]),
            -14,
        )?;
        check(
            seq,
            "pipe-write-copy-before-effect",
            raw(13, [pipe[1] as u64, pointer, 8, 0, 0, 0]),
            -14,
        )?;
    }
    for bad in [
        b"".as_slice(),
        b"/",
        b"/.",
        b"/..",
        b"/a/b",
        b"/a\0b",
        b"relative",
    ] {
        let ptr = bad.as_ptr() as u64;
        let len = bad.len() as u64;
        for (n, a) in [
            (10, [ptr, len, 1, 0, 0, 0]),
            (16, [ptr, len, page, 0, 0, 0]),
            (18, [ptr, len, 0, 0, 0, 0]),
            (19, [ptr, len, path, 7, 0, 0]),
        ] {
            check_call(seq, "invalid-path", n, a, -22)?;
        }
    }
    for handle in [32, u64::MAX] {
        for n in [11, 12, 13, 14, 15, 21] {
            let mut a = [0; 6];
            a[0] = handle;
            if n == 12 || n == 13 {
                a[1] = u64::MAX;
                a[2] = 4097;
            }
            check_call(seq, "invalid-descriptor-precedence", n, a, -9)?;
        }
    }
    for (n, handle) in [
        (12, write_only),
        (13, read_only),
        (12, pipe[1]),
        (13, pipe[0]),
    ] {
        check(
            seq,
            "wrong-rights",
            raw(n, [handle as u64, u64::MAX, 0, 0, 0, 0]),
            -9,
        )?;
    }
    for n in [12, 13] {
        check(
            seq,
            "io-zero-pointer-exception",
            raw(n, [fd as u64, u64::MAX, 0, 0, 0, 0]),
            0,
        )?;
        for length in [4097, u64::MAX] {
            check(
                seq,
                "io-invalid-length",
                raw(n, [fd as u64, u64::MAX, length, 0, 0, 0]),
                -22,
            )?;
        }
    }
    for flags in [0, 4, 0x201, 0x401, 0x803, u64::MAX] {
        check(
            seq,
            "open-invalid-flags",
            raw(10, [path, 7, flags, 0, 0, 0]),
            -22,
        )?;
    }
    for n in [8, 10, 16, 18] {
        check(
            seq,
            "path-overlong-before-pointer",
            raw(n, [u64::MAX, 49, 0, 0, 0, 0]),
            -36,
        )?;
    }
    check(
        seq,
        "spawn-argc-overflow",
        raw(8, [exec, 18, 0, 17, stdio_ptr, 0]),
        -7,
    )?;
    check(
        seq,
        "spawn-missing-stdio",
        rt::spawn(readonly_name, &[], [32, -1, -1]).unwrap_err(),
        -9,
    )?;
    check(
        seq,
        "spawn-wrong-stdin",
        rt::spawn(readonly_name, &[], [write_only as i32, -1, -1]).unwrap_err(),
        -9,
    )?;
    check(
        seq,
        "spawn-wrong-stdout",
        rt::spawn(readonly_name, &[], [-1, read_only as i32, -1]).unwrap_err(),
        -9,
    )?;
    check(
        seq,
        "list-invalid-capacity",
        raw(17, [u64::MAX, 257, 0, 0, 0, 0]),
        -22,
    )?;
    check(
        seq,
        "ps-invalid-capacity",
        raw(22, [u64::MAX, 65, 0, 0, 0, 0]),
        -22,
    )?;
    check(
        seq,
        "ps-zero-capacity",
        raw(22, [u64::MAX, 0, 0, 0, 0, 0]),
        -105,
    )?;
    check(seq, "trace-stop", raw(0x4b545243, [1, 0, 0, 0, 0, 0]), 0)?;
    condition(seq, "rejections-owner-census", census()? == owners)?;
    let mut trace_header = [0u64; 4];
    check(
        seq,
        "trace-header",
        raw(
            0x4b545243,
            [2, trace_header.as_mut_ptr() as u64, 0, 0, 0, 0],
        ),
        0,
    )?;
    condition(seq, "invalid-file-no-block-request", trace_header[2] == 0)?;
    let mut offset = 0;
    while offset < trace_header[1] {
        let n = (trace_header[1] - offset).min(100);
        let mut rows = [0u64; 500];
        check(
            seq,
            "trace-read",
            raw(0x4b545243, [3, rows.as_mut_ptr() as u64, n, offset, 0, 0]),
            n as i64,
        )?;
        condition(
            seq,
            "invalid-file-no-block-request",
            (0..n as usize).all(|i| rows[i * 5 + 2] != 7),
        )?;
        offset += n;
    }
    // Zero is a valid capacity: discovering a nonempty directory requires
    // metadata reads. Its ENOBUFS is distinct from malformed scalar/pointer
    // rejection above; verify the pointer exception separately.
    check(
        seq,
        "list-zero-capacity",
        raw(17, [u64::MAX, 0, 0, 0, 0, 0]),
        -105,
    )?;
    let mut small = [0u8; 8];
    condition(
        seq,
        "pipe-data-authoritative",
        rt::read(pipe[0], &mut small)? == 4 && &small[..4] == b"safe",
    )?;
    rt::close(pipe[1])?;
    condition(
        seq,
        "pipe-no-appended-data",
        rt::read(pipe[0], &mut small)? == 0,
    )?;
    rt::close(pipe[0])?;
    // fd was at EOF before invalid calls. An invalid read with actual result
    // shorter than the range must still fail, preserving its shared offset.
    condition(seq, "file-offset-preserved", rt::read(fd, &mut small)? == 0)?;
    rt::seek(fd, 0)?;
    let mut got = [0u8; 4096];
    condition(
        seq,
        "file-bytes-preserved",
        rt::read(fd, &mut got)? == 4096 && got == data,
    )?;
    check(
        seq,
        "seek-too-large",
        raw(14, [fd as u64, 4097, 0, 0, 0, 0]),
        -22,
    )?;
    check(
        seq,
        "seek-overflow",
        raw(14, [fd as u64, u64::MAX, 0, 0, 0, 0]),
        -22,
    )?;
    check(seq, "seek-console", raw(14, [1, 0, 0, 0, 0, 0]), -29)?;
    condition(seq, "seek-min", rt::seek(fd, 0)? == 0)?;
    condition(seq, "seek-max", rt::seek(fd, 4096)? == 4096)?;
    rt::fsync(fd)?;
    let bulk = rt::page_alloc(6)?;
    let cross = bulk + 4095;
    check_call(seq, "abi-valid-cross-page", 0, [cross, 0, 0, 0, 0, 0], 0)?;
    condition(
        seq,
        "abi-wire-valid",
        unsafe { core::slice::from_raw_parts(cross as *const u8, 32) } == rt::abi::abi_info(),
    )?;
    check_call(
        seq,
        "stat-valid-cross-page",
        16,
        [path, 7, cross, 0, 0, 0],
        0,
    )?;
    check_call(
        seq,
        "list-max-valid-cross-page",
        17,
        [cross, 256, 0, 0, 0, 0],
        2,
    )?;
    check_call(
        seq,
        "process-list-max-cross-page",
        22,
        [cross, 64, 0, 0, 0, 0],
        1,
    )?;
    check_call(
        seq,
        "pipe-output-valid-cross-page",
        20,
        [cross, 0, 0, 0, 0, 0],
        0,
    )?;
    let pair = unsafe { core::ptr::read_unaligned(cross as *const [u32; 2]) };
    unsafe {
        core::ptr::write_unaligned(cross as *mut [u8; 2], *b"ok");
    }
    check_call(
        seq,
        "pipe-source-valid-cross-page",
        13,
        [pair[1] as u64, cross, 2, 0, 0, 0],
        2,
    )?;
    check_call(
        seq,
        "pipe-output-valid-cross-page",
        12,
        [pair[0] as u64, cross, 2, 0, 0, 0],
        2,
    )?;
    condition(
        seq,
        "pipe-cross-page-bytes",
        unsafe { core::ptr::read_unaligned(cross as *const [u8; 2]) } == *b"ok",
    )?;
    rt::close(pair[0])?;
    rt::close(pair[1])?;
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), cross as *mut u8, name.len());
    }
    let opened = raw(10, [cross, 7, 1, 0, 0, 0]);
    condition(seq, "open-valid-cross-page", opened >= 0)?;
    rt::close(opened as u32)?;
    // Each individual spawn input crosses a mapped page boundary.
    unsafe {
        core::ptr::copy_nonoverlapping(readonly_name.as_ptr(), cross as *mut u8, 18);
        core::ptr::write_unaligned((bulk + 8190) as *mut [i32; 3], [-1; 3]);
        core::ptr::copy_nonoverlapping(b"authority".as_ptr(), (bulk + 16380) as *mut u8, 9);
        core::ptr::write_unaligned((bulk + 12280) as *mut [u64; 2], [bulk + 16380, 9]);
    }
    let spawned = raw(8, [cross, 18, bulk + 12280, 1, bulk + 8190, 0]);
    condition(seq, "spawn-all-inputs-cross-page", spawned > 0)?;
    check_call(
        seq,
        "wait-valid-cross-page",
        9,
        [spawned as u64, cross, 0, 0, 0, 0],
        spawned,
    )?;
    condition(
        seq,
        "wait-valid-status",
        unsafe { core::ptr::read_unaligned((cross + 8) as *const u32) } == 0,
    )?;
    unsafe { rt::page_free(bulk, 6) }?;
    let minimum = rt::page_alloc(1)?;
    check_call(
        seq,
        "process-list-min-capacity",
        22,
        [minimum, 1, 0, 0, 0, 0],
        1,
    )?;
    unsafe {
        core::ptr::write_bytes(minimum as *mut u8, 0xaa, 64);
    }
    check_call(
        seq,
        "list-insufficient-capacity-no-copy",
        17,
        [minimum, 1, 0, 0, 0, 0],
        -105,
    )?;
    condition(
        seq,
        "list-insufficient-output-preserved",
        unsafe { core::slice::from_raw_parts(minimum as *const u8, 64) }
            .iter()
            .all(|b| *b == 0xaa),
    )?;
    unsafe { rt::page_free(minimum, 1) }?;
    let alias = rt::dup(fd)?;
    rt::seek(alias, 0)?;
    let child = rt::spawn(
        readonly_name,
        &[b"shared"],
        [-1, alias as i32, alias as i32],
    )?;
    condition(
        seq,
        "duplicate-stdio-shared-offset",
        rt::wait(child, false)?.code == 0
            && rt::read(fd, &mut small[..1])? == 1
            && small[0] == 0x39,
    )?;
    rt::close(alias)?;
    let pid = rt::spawn(readonly_name, &[], [-1, -1, -1])?;
    rt::yield_now()?;
    for pointer in [0, 0x18000000, page + 4095, u64::MAX - 1] {
        check(
            seq,
            "wait-full-output",
            raw(9, [pid, pointer, 0, 0, 0, 0]),
            -14,
        )?;
    }
    check(
        seq,
        "wait-invalid-flags",
        raw(9, [pid, page, 2, 0, 0, 0]),
        -22,
    )?;
    check(
        seq,
        "wait-invalid-pid",
        raw(9, [u64::MAX, page, 0, 0, 0, 0]),
        -22,
    )?;
    condition(
        seq,
        "wait-zombie-preserved",
        rt::wait(pid, false)?.code == 0,
    )?;
    check(seq, "wait-stale", rt::wait(pid, false).unwrap_err(), -10)?;
    for d in [fd, read_only, write_only] {
        rt::close(d)?;
    }
    let long = [b'x'; 48];
    let mut longpath = long;
    longpath[0] = b'/';
    let longfd = rt::open(&longpath, 3 | 0x100 | 0x200)?;
    rt::close(longfd)?;
    rt::unlink(&longpath)?;
    rt::unlink(name)?;
    unsafe { rt::page_free(page, 1) }?;
    // Remove the now-unused executable fixture deliberately, then exercise
    // the empty-set zero-capacity pointer exception at the actual syscall.
    rt::unlink(readonly_name)?;
    check_call(
        seq,
        "list-empty-zero-pointer",
        17,
        [u64::MAX, 0, 0, 0, 0, 0],
        0,
    )?;
    let mut empty = [0xaau8; 64];
    check_call(
        seq,
        "list-empty-positive-capacity",
        17,
        [empty.as_mut_ptr() as u64, 1, 0, 0, 0, 0],
        0,
    )?;
    condition(
        seq,
        "list-empty-output-untouched",
        empty.iter().all(|b| *b == 0xaa),
    )?;
    condition(seq, "all-owners-restored", census()? == initial)?;
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    let mut seq = 1;
    emit(seq, "start", format_args!(""));
    let result = work(&mut seq);
    seq += 1;
    emit(
        seq,
        "result",
        format_args!(
            ",\"result\":\"{}\",\"error\":{}",
            if result.is_ok() { "PASS" } else { "FAIL" },
            result.err().unwrap_or(0)
        ),
    );
    let _ = rt::shutdown();
    127
}
