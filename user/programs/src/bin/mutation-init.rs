#![no_std]
#![no_main]
//! Immutable supervisor for independently mutated kernel candidates.
use core::fmt::{self, Write};
use user_runtime as rt;
rt::entry!(main);

struct Json {
    bytes: [u8; 512],
    length: usize,
}
impl Write for Json {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > self.bytes.len() - self.length {
            return Err(fmt::Error);
        }
        self.bytes[self.length..self.length + value.len()].copy_from_slice(value.as_bytes());
        self.length += value.len();
        Ok(())
    }
}
fn emit(sequence: u64, event: &str, fields: fmt::Arguments<'_>) {
    let mut json = Json {
        bytes: [0; 512],
        length: 0,
    };
    write!(&mut json,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"kernel-mutations\",\"sequence\":{},\"event\":\"{}\"",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),sequence,event).unwrap();
    json.write_fmt(fields).unwrap();
    json.write_str("}").unwrap();
    // SAFETY: immutable init owns the fully initialized bounded JSON buffer.
    if unsafe {
        rt::raw(
            0x4b544553,
            [json.bytes.as_ptr() as u64, json.length as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        rt::exit(127);
    }
}
fn preserved_pipe_bytes() -> rt::Result<bool> {
    let base = rt::page_alloc(1)?;
    let pair = rt::pipe()?;
    let expected = b"unchanged bytes";
    rt::write_all(pair[1], expected).map_err(|error| error.error)?;
    // SAFETY: this deliberately invalid cross-page destination exercises EFAULT.
    let bad = unsafe {
        rt::raw(
            12,
            [pair[0] as u64, base + 4088, expected.len() as u64, 0, 0, 0],
        )
    };
    rt::close(pair[1])?;
    let mut received = [0u8; 15];
    let length = rt::read(pair[0], &mut received)?;
    rt::close(pair[0])?;
    // SAFETY: the exact live anonymous allocation is no longer used.
    unsafe {
        rt::page_free(base, 1)?;
    }
    Ok(bad == -14 && length == expected.len() && received == *expected)
}
fn probe(mode: &[u8], cause: u64) -> rt::Result<bool> {
    let child = rt::spawn(b"/fault-probe", &[mode], [-1, -1, -1])?;
    let result = rt::wait(child, false)?;
    Ok(result.kind == 1 && result.cause == cause)
}
fn waiter() -> rt::Result<bool> {
    let child = rt::spawn(b"/race-reader", &[], [-1, -1, -1])?;
    // A correct reader/writer exchange completes in two dispatches. The finite
    // guest-time deadline exposes a deliberately widened registration race.
    rt::sleep(100)?;
    match rt::wait(child, true) {
        Ok(status) => Ok(status.kind == 0 && status.code == 0),
        Err(-11) => Ok(false),
        Err(error) => Err(error),
    }
}
fn main(_: &[&[u8]]) -> i32 {
    emit(1, "start", format_args!(""));
    type Case = (&'static str, fn() -> rt::Result<bool>);
    let cases: [Case; 4] = [
        ("copyout-before-consume", preserved_pipe_bytes),
        ("writable-executable", || probe(b"text", 15)),
        ("translation-invalidation", || probe(b"freed", 13)),
        ("waiter-registration", waiter),
    ];
    let mut pass = true;
    for (index, (name, run)) in cases.iter().enumerate() {
        let result = run();
        let ok = matches!(result, Ok(true));
        pass &= ok;
        emit(
            index as u64 + 2,
            "assertion",
            format_args!(
                ",\"assertion\":\"{}\",\"result\":\"{}\",\"error\":{}",
                name,
                if ok { "PASS" } else { "FAIL" },
                result.err().unwrap_or(0)
            ),
        );
    }
    emit(
        6,
        "result",
        format_args!(",\"result\":\"{}\"", if pass { "PASS" } else { "FAIL" }),
    );
    let _ = rt::shutdown();
    127
}
