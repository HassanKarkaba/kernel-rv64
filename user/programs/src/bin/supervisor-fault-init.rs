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
    let case = "supervisor-fault";
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
fn main(_: &[&[u8]]) -> i32 {
    emit(1, "start", format_args!(""));
    let mode = u64::from(env!("KERNEL_DEVICE_FAULT").as_bytes()[0] - b'0');
    // SAFETY: init-only instrumented call deliberately requests a fatal supervisor fault.
    unsafe {
        rt::raw(0x4b544652, [mode, 0, 0, 0, 0, 0]);
    }
    127
}
