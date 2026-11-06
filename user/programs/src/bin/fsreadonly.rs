#![no_std]
#![no_main]
//! Immutable init exercising READ_ONLY/FAILED through the ordinary syscall ABI.
use core::fmt::{self, Write};
use user_runtime as rt;
rt::entry!(main);
struct Text {
    bytes: [u8; 768],
    length: usize,
}
impl Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() > self.bytes.len() - self.length {
            return Err(fmt::Error);
        }
        self.bytes[self.length..self.length + text.len()].copy_from_slice(text.as_bytes());
        self.length += text.len();
        Ok(())
    }
}
struct Test {
    sequence: u64,
    pass: bool,
}
impl Test {
    fn emit(&mut self, event: &str, fields: fmt::Arguments<'_>) {
        self.sequence += 1;
        let mut text = Text {
            bytes: [0; 768],
            length: 0,
        };
        write!(&mut text,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"readonly-open\",\"sequence\":{},\"event\":\"{}\"",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),self.sequence,event).unwrap();
        text.write_fmt(fields).unwrap();
        text.write_str("}").unwrap();
        // SAFETY: init owns this complete initialized immutable record. Release
        // kernels return ENOSYS, in which case this sole init writes a visible record.
        let result = unsafe {
            rt::raw(
                0x4b544553,
                [text.bytes.as_ptr() as u64, text.length as u64, 0, 0, 0, 0],
            )
        };
        if result == -38 {
            let _ = rt::write_all(1, b"ROTEST ");
            let _ = rt::write_all(1, &text.bytes[..text.length]);
            let _ = rt::write_all(1, b"\n");
        } else if result != 0 {
            rt::exit(127);
        }
    }
    fn check(&mut self, name: &str, actual: i64, expected: i64) {
        self.pass &= actual == expected;
        self.emit(
            "check",
            format_args!(
                ",\"name\":\"{}\",\"actual\":{},\"expected\":{}",
                name, actual, expected
            ),
        );
    }
    fn phase(&mut self, name: &str) -> rt::Result<()> {
        self.emit("phase", format_args!(",\"name\":\"{}\"", name));
        let mut byte = [0];
        if rt::read(0, &mut byte)? != 1 {
            return Err(-5);
        }
        Ok(())
    }
    fn counts(&mut self, name: &str, counts: Option<[u64; 12]>) {
        if let Some(values) = counts {
            self.emit(
                "owners",
                format_args!(",\"name\":\"{}\",\"counts\":{:?}", name, values),
            );
        } else {
            self.emit("owners-unavailable", format_args!(",\"name\":\"{}\"", name));
        }
    }
}
fn status<T>(value: rt::Result<T>) -> i64 {
    match value {
        Ok(_) => 0,
        Err(e) => e,
    }
}
fn census() -> rt::Result<Option<[u64; 12]>> {
    let mut bytes = [0u8; 128];
    // SAFETY: the private observation copies into this complete live output.
    let n = unsafe { rt::raw(0x4b544d45, [9, bytes.as_mut_ptr() as u64, 128, 0, 0, 0]) };
    if n == -38 {
        return Ok(None);
    }
    if n != 128 {
        return Err(if n < 0 { n } else { -5 });
    }
    Ok(Some(core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[8 + i * 8..16 + i * 8].try_into().unwrap())
    })))
}
fn run(test: &mut Test, mode: u8) -> rt::Result<()> {
    let failed = mode == b'F';
    let writable = mode != b'M';
    let baseline = census()?;
    test.counts("baseline", baseline);
    let fd = rt::open(b"/payload", if writable { 3 } else { 1 })?;
    if mode == b'T' {
        test.check("last_transaction", status(rt::write(fd, b"Z")), 0);
    }
    test.check("initial_seek", status(rt::seek(fd, 7)), 0);
    if failed {
        test.phase("fault_armed")?;
        let mut byte = [0];
        test.check("trigger_read_error", status(rt::read(fd, &mut byte)), -5);
    }
    let before = census()?;
    test.counts("before_denied", before);
    test.phase("denied_begin")?;
    let expected = if failed { -5 } else { -30 };
    for (name, path, flags) in [
        ("write_existing", &b"/payload"[..], 2),
        ("readwrite_existing", &b"/payload"[..], 3),
        ("create_read_existing", &b"/payload"[..], 0x101),
        ("create_write_existing", &b"/payload"[..], 0x102),
        ("create_missing", &b"/missing"[..], 0x103),
        ("create_exclusive_existing", &b"/payload"[..], 0x303),
        ("truncate_existing", &b"/payload"[..], 0x402),
        ("truncate_empty", &b"/empty"[..], 0x403),
    ] {
        let result = rt::open(path, flags);
        let actual = match result {
            Ok(value) => value as i64,
            Err(error) => error,
        };
        test.check(name, actual, expected);
        if let Ok(extra) = result {
            rt::close(extra)?;
        }
    }
    test.check(
        "invalid_flags_before_state",
        status(rt::open(b"/payload", 0x8001)),
        -22,
    );
    test.check(
        "invalid_path_before_state",
        status(rt::open(b"bad/name", 2)),
        -22,
    );
    // SAFETY: deliberately invalid ABI address, never dereferenced by this program.
    let bad_pointer = unsafe { rt::raw(rt::abi::Syscall::Open as u64, [1, 8, 2, 0, 0, 0]) };
    test.check("bad_pointer_before_state", bad_pointer, -14);
    let mut rejected = 0;
    for _ in 0..300 {
        match rt::open(b"/payload", 3) {
            Err(e) if e == expected => rejected += 1,
            Ok(extra) => {
                rt::close(extra)?;
            }
            _ => {}
        }
    }
    test.check("repeated_denials", rejected, 300);
    let after = census()?;
    test.counts("after_denied", after);
    test.check("denial_owner_counts", i64::from(before != after), 0);
    test.phase("denied_end")?;
    // Both malformed pointers are ignored for a valid zero-length operation;
    // access rights still precede the no-effect exception.
    let zero_read = unsafe {
        rt::raw(
            rt::abi::Syscall::Read as u64,
            [fd as u64, u64::MAX, 0, 0, 0, 0],
        )
    };
    let zero_write = unsafe {
        rt::raw(
            rt::abi::Syscall::Write as u64,
            [fd as u64, u64::MAX, 0, 0, 0, 0],
        )
    };
    test.check("zero_read_invalid_pointer", zero_read, 0);
    test.check(
        "zero_write_invalid_pointer",
        zero_write,
        if writable { 0 } else { -9 },
    );
    let mut records = [[0u8; 64]; 4];
    let mut byte = [0];
    if failed {
        test.check("failed_read_open", status(rt::open(b"/payload", 1)), -5);
        test.check("failed_read", status(rt::read(fd, &mut byte)), -5);
        test.check("failed_write", status(rt::write(fd, b"Q")), -5);
        test.check("failed_seek", status(rt::seek(fd, 0)), -5);
        test.check("failed_stat", status(rt::stat(b"/payload")), -5);
        test.check("failed_list", status(rt::list(&mut records)), -5);
        test.check("failed_fsync", status(rt::fsync(fd)), -5);
        test.check(
            "failed_spawn",
            status(rt::spawn(b"/payload", &[], [0, 1, 2])),
            -5,
        );
    } else {
        test.check(
            "offset_survives_denied_open",
            status(rt::read(fd, &mut byte)),
            0,
        );
        test.check("offset_byte", byte[0] as i64, b'h' as i64);
        test.check("permitted_seek", status(rt::seek(fd, 7)), 0);
        test.check("permitted_stat", status(rt::stat(b"/payload")), 0);
        test.check("permitted_list", status(rt::list(&mut records)), 0);
        test.check("permitted_fsync", status(rt::fsync(fd)), 0);
        let read_fd = rt::open(b"/payload", 1)?;
        test.check("read_open", 0, 0);
        rt::close(read_fd)?;
        test.check("missing_read_open", status(rt::open(b"/missing", 1)), -2);
        test.check(
            "readonly_nonzero_write",
            status(rt::write(fd, b"Q")),
            if writable { -30 } else { -9 },
        );
        test.check("readonly_unlink", status(rt::unlink(b"/payload")), -30);
        test.check(
            "readonly_same_rename",
            status(rt::rename(b"/payload", b"/payload")),
            -30,
        );
    }
    rt::close(fd)?;
    test.check("close", 0, 0);
    if !failed {
        let mut descriptors = [0u32; 29];
        for (i, slot) in descriptors.iter_mut().enumerate() {
            *slot = rt::open(b"/payload", 1)?;
            if *slot != 3 + i as u32 {
                return Err(-5);
            }
        }
        test.check("descriptor_capacity", 29, 29);
        test.check("full_table_read", status(rt::open(b"/payload", 1)), -24);
        test.check(
            "full_table_write_precedence",
            status(rt::open(b"/payload", 2)),
            -24,
        );
        for descriptor in descriptors {
            rt::close(descriptor)?;
        }
    }
    let pipe = rt::pipe()?;
    rt::write(pipe[1], b"ok")?;
    let mut bytes = [0; 2];
    rt::read(pipe[0], &mut bytes)?;
    test.check("pipe_containment", i64::from(bytes != *b"ok"), 0);
    rt::close(pipe[0])?;
    rt::close(pipe[1])?;
    let memory = rt::page_alloc(1)?;
    // SAFETY: this is the exact live allocation owned by init, without aliases.
    unsafe {
        rt::page_free(memory, 1)?;
    }
    let final_counts = census()?;
    test.counts("final", final_counts);
    test.check("final_owner_counts", i64::from(final_counts != baseline), 0);
    test.phase("operations_end")?;
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    let mut test = Test {
        sequence: 0,
        pass: true,
    };
    test.emit("start", format_args!(""));
    let mut mode = [0];
    let result = rt::read(0, &mut mode).and_then(|n| {
        if n == 1 && matches!(mode[0], b'M' | b'T' | b'F') {
            run(&mut test, mode[0])
        } else {
            Err(-22)
        }
    });
    let error = status(result);
    test.pass &= error == 0;
    test.emit(
        "result",
        format_args!(
            ",\"result\":\"{}\",\"error\":{}",
            if test.pass { "PASS" } else { "FAIL" },
            error
        ),
    );
    let _ = rt::shutdown();
    if test.pass { 0 } else { 1 }
}
