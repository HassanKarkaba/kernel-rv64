#![no_std]
#![no_main]
//! Immutable init exercising full data-block/inode capacity through the ordinary syscall ABI.
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
        write!(&mut text,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"storage-capacity\",\"sequence\":{},\"event\":\"{}\"",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),self.sequence,event).unwrap();
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
fn run(test: &mut Test) -> rt::Result<()> {
    let baseline = census()?;
    test.counts("baseline", baseline);
    let empty = rt::open(b"/f016", 3)?;
    let grow = rt::open(b"/f015", 3)?;
    let maximum = rt::open(b"/f001", 3)?;
    rt::seek(grow, 3_997_696)?;
    rt::seek(maximum, 4_194_304)?;
    let before = census()?;
    test.counts("before_full", before);
    let block = [b'G'; 4096];
    test.phase("full_begin")?;
    test.check("empty_needs_data", status(rt::write(empty, b"N")), -28);
    test.check("growth_needs_data", status(rt::write(grow, &block)), -28);
    test.check("create_needs_inode", status(rt::open(b"/new", 0x303)), -28);
    test.check("maximum_file_write", status(rt::write(maximum, b"X")), -27);
    test.check(
        "maximum_file_seek",
        status(rt::seek(maximum, 4_194_305)),
        -22,
    );
    let after = census()?;
    test.counts("after_full", after);
    test.check("full_owner_counts", i64::from(before != after), 0);
    test.phase("full_end")?;
    rt::close(maximum)?;
    test.check("release_file", status(rt::unlink(b"/f000")), 0);
    test.phase("reclaimed")?;
    let new = rt::open(b"/new", 0x303)?;
    test.check("retry_create", 0, 0);
    // Do not seek: these successful retries prove failed writes retained offsets.
    test.check(
        "retry_empty_offset",
        rt::write(empty, b"N")
            .map(|n| n as i64)
            .unwrap_or_else(|e| e),
        1,
    );
    test.check(
        "retry_growth_offset",
        rt::write(grow, &block)
            .map(|n| n as i64)
            .unwrap_or_else(|e| e),
        4096,
    );
    let mut data = [0u8; 4096];
    for index in 0..13u8 {
        data.fill(b'0' + index);
        test.check(
            "direct_indirect_write",
            rt::write(new, &data)
                .map(|n| n as i64)
                .unwrap_or_else(|e| e),
            4096,
        );
    }
    test.check("inode_full_again", status(rt::open(b"/again", 0x303)), -28);
    rt::seek(empty, 0)?;
    let mut one = [0];
    rt::read(empty, &mut one)?;
    test.check("empty_readback", one[0] as i64, b'N' as i64);
    rt::seek(grow, 3_997_696)?;
    rt::read(grow, &mut data)?;
    test.check("growth_readback", i64::from(data != block), 0);
    rt::seek(new, 12 * 4096)?;
    rt::read(new, &mut data)?;
    test.check("indirect_readback", i64::from(data != [b'<'; 4096]), 0);
    test.check("new_fsync", status(rt::fsync(new)), 0);
    rt::close(empty)?;
    rt::close(grow)?;
    rt::close(new)?;
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
    let error = status(run(&mut test));
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
