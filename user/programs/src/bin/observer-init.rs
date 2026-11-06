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
    let case = "observation-boundaries";
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
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn control(op: u64, pointer: u64, count: u64, offset: u64) -> rt::Result<u64> {
    // SAFETY: only owned output arrays and scalar selectors are passed below.
    let value = unsafe { rt::raw(0x4b545243, [op, pointer, count, offset, 0, 0]) };
    if value < 0 {
        Err(value)
    } else {
        Ok(value as u64)
    }
}
fn workload() -> rt::Result<()> {
    let pid = rt::spawn(b"/observer-worker", &[], [-1, -1, -1])?;
    let result = unsafe { rt::raw(0x4b54494c, [4, 0, 0, 0, 0, 0]) };
    if result != 0 {
        return Err(result);
    }
    if rt::wait(pid, false)?.code != 0 {
        return Err(-5);
    }
    Ok(())
}
fn work(sequence: &mut u64) -> rt::Result<bool> {
    control(0, 0, 0, 0)?;
    let result = workload();
    control(1, 0, 0, 0)?;
    result?;
    let mut header = [0u8; 32];
    control(2, header.as_mut_ptr() as u64, 0, 0)?;
    let count = u64_at(&header, 8);
    let lost = u64_at(&header, 16);
    *sequence += 1;
    emit(
        *sequence,
        "summary",
        format_args!(
            ",\"trace_schema\":{},\"count\":{},\"lost\":{},\"frequency\":{}",
            u64_at(&header, 0),
            count,
            lost,
            u64_at(&header, 24)
        ),
    );
    let mut offset = 0;
    while offset < count {
        let n = (count - offset).min(100);
        let mut bytes = [0u8; 4000];
        if control(3, bytes.as_mut_ptr() as u64, n, offset)? != n {
            return Err(-5);
        }
        for i in 0..n as usize {
            let row = &bytes[i * 40..i * 40 + 40];
            *sequence += 1;
            emit(
                *sequence,
                "trace",
                format_args!(
                    ",\"ordinal\":{},\"ticks\":{},\"kind\":{},\"object\":{},\"detail\":{}",
                    u64_at(row, 0),
                    u64_at(row, 8),
                    u64_at(row, 16),
                    u64_at(row, 24),
                    u64_at(row, 32)
                ),
            );
        }
        offset += n;
    }
    control(0, 0, 0, 0)?;
    for _ in 0..10000 {
        rt::getpid()?;
    }
    control(1, 0, 0, 0)?;
    let mut overflow = [0u8; 32];
    control(2, overflow.as_mut_ptr() as u64, 0, 0)?;
    let retained = u64_at(&overflow, 8);
    let discarded = u64_at(&overflow, 16);
    let mut first = [0u8; 40];
    let mut last = [0u8; 40];
    control(3, first.as_mut_ptr() as u64, 1, 0)?;
    control(3, last.as_mut_ptr() as u64, 1, retained - 1)?;
    *sequence += 1;
    emit(
        *sequence,
        "overflow",
        format_args!(
            ",\"retained\":{},\"lost\":{},\"first\":{},\"last\":{}",
            retained,
            discarded,
            u64_at(&first, 0),
            u64_at(&last, 0)
        ),
    );
    Ok(lost == 0
        && count > 0
        && retained == 8192
        && discarded >= 1809
        && u64_at(&first, 0) == discarded + 1
        && u64_at(&last, 0) == discarded + retained)
}
fn main(_: &[&[u8]]) -> i32 {
    let mut sequence = 1;
    emit(sequence, "start", format_args!(""));
    let good = matches!(work(&mut sequence), Ok(true));
    sequence += 1;
    emit(
        sequence,
        "result",
        format_args!(",\"result\":\"{}\"", if good { "PASS" } else { "FAIL" }),
    );
    let _ = rt::shutdown();
    127
}
