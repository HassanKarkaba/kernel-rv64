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
    let case = "loader-boundaries";
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
fn ownership() -> rt::Result<[u8; 128]> {
    let mut bytes = [0u8; 128];
    // SAFETY: immutable init owns this entire writable census buffer.
    let value = unsafe { rt::raw(0x4b544d45, [9, bytes.as_mut_ptr() as u64, 128, 0, 0, 0]) };
    if value < 0 { Err(value) } else { Ok(bytes) }
}
fn work() -> rt::Result<bool> {
    let before = ownership()?;
    for index in 0..20u8 {
        let path = [b'/', b'b', b'a', b'd', b'0' + index / 10, b'0' + index % 10];
        let expected = if index == 19 { -7 } else { -8 };
        if rt::spawn(&path, &[], [-1, -1, -1]) != Err(expected) || ownership()? != before {
            return Ok(false);
        }
    }
    if rt::spawn(b"/valid", &[b"a\0b"], [-1, -1, -1]) != Err(-22) {
        return Ok(false);
    }
    if rt::spawn(b"/valid", &[&[b'x'; 256]], [-1, -1, -1]) != Err(-7) {
        return Ok(false);
    }
    let long = [b'x'; 255];
    if rt::spawn(
        b"/valid",
        &[&long, &long, &long, &long, &long],
        [-1, -1, -1],
    ) != Err(-7)
    {
        return Ok(false);
    }
    // SAFETY: scalar rejection of excessive count precedes following these invalid pointers.
    if unsafe { rt::raw(8, [b"/valid".as_ptr() as u64, 6, u64::MAX, 17, u64::MAX, 0]) } != -7 {
        return Ok(false);
    }
    if ownership()? != before {
        return Ok(false);
    }
    let child = rt::spawn(b"/valid", &[b"exit"], [-1, -1, -1])?;
    let status = rt::wait(child, false)?;
    Ok(status.kind == 0 && status.code == 0 && ownership()? == before)
}
fn main(_: &[&[u8]]) -> i32 {
    emit(1, "start", format_args!(""));
    emit(
        2,
        "result",
        format_args!(
            ",\"result\":\"{}\",\"malformed_elf_cases\":20,\"argument_cases\":4",
            if matches!(work(), Ok(true)) {
                "PASS"
            } else {
                "FAIL"
            }
        ),
    );
    let _ = rt::shutdown();
    127
}
