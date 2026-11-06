#![no_std]
#![no_main]
use core::fmt::{self, Write};
use user_runtime as rt;
rt::entry!(main);
const MODE: &str = match option_env!("KERNEL_UART_CASE") {
    Some(value) => value,
    None => "short",
};
const PADDING: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
struct Json {
    bytes: [u8; 512],
    len: usize,
}
impl Write for Json {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.len + text.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
        Ok(())
    }
}
fn emit(sequence: u64, event: &str, result: &str) -> i64 {
    let mut out = Json {
        bytes: [0; 512],
        len: 0,
    };
    if write!(&mut out, "{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"uart-{}\",\"sequence\":{},\"event\":\"{}\",\"result\":\"{}\",\"padding\":\"{}\"}}", env!("KERNEL_TEST_RUN_ID"), env!("KERNEL_TEST_BOOT_ID"), MODE, sequence, event, result, PADDING).is_err() {
        return -22;
    }
    // SAFETY: the owned bounded record remains live and immutable during ecall.
    unsafe {
        rt::raw(
            0x4b54_4553,
            [out.bytes.as_ptr() as u64, out.len as u64, 0, 0, 0, 0],
        )
    }
}
fn counters() -> Option<(u64, u64)> {
    let mut bytes = [0u8; 16];
    // SAFETY: the owned output is writable for all 16 bytes for this ecall.
    let status = unsafe { rt::raw(0x4b54_5541, [bytes.as_mut_ptr() as u64, 16, 0, 0, 0, 0]) };
    if status != 0 {
        return None;
    }
    Some((
        u64::from_le_bytes(bytes[..8].try_into().ok()?),
        u64::from_le_bytes(bytes[8..].try_into().ok()?),
    ))
}
fn persist(value: &[u8]) -> bool {
    let Ok(fd) = rt::open(b"/uart-result", 2 | 0x100 | 0x200) else {
        return false;
    };
    let valid = rt::write_all(fd, value).is_ok() && rt::fsync(fd).is_ok();
    rt::close(fd).is_ok() && valid
}
fn run() -> bool {
    if counters() != Some((0, 0)) || emit(1, "start", "") != 0 {
        return false;
    }
    rt::print(format_args!("UART_PROBE_READY\n"));
    let mut gate = [0];
    if rt::read(0, &mut gate) != Ok(1) || gate != *b"s" {
        return false;
    }
    match MODE {
        "short" => {
            for sequence in 2..=2001 {
                if emit(sequence, "data", "") != 0 {
                    return false;
                }
            }
            persist(b"SHORT_OK") && emit(2002, "result", "PASS") == 0
        }
        "timeout" => {
            let mut failed = false;
            for sequence in 2..=2001 {
                let status = emit(sequence, "data", "");
                if status == -5 {
                    failed = true;
                    break;
                }
                if status != 0 {
                    return false;
                }
            }
            if !failed || rt::sleep(2000).is_err() {
                return false;
            }
            let sticky = emit(2002, "result", "PASS") == -5 && counters() == Some((0, 1));
            sticky && persist(b"TIMEOUT_STICKY")
        }
        "oversize" | "pointer" => {
            let bytes = [0u8; 512];
            let (pointer, length, expected) = if MODE == "oversize" {
                (bytes.as_ptr() as u64, 513, -22)
            } else {
                (0, 1, -14)
            };
            // SAFETY: deliberate kernel pointer/length validation probe; the
            // kernel must reject before dereferencing the invalid user range.
            let status = unsafe { rt::raw(0x4b54_4553, [pointer, length, 0, 0, 0, 0]) };
            let sticky =
                status == expected && emit(2, "result", "PASS") == -5 && counters() == Some((0, 1));
            sticky
                && persist(if MODE == "oversize" {
                    b"OVERSIZE_STICKY"
                } else {
                    b"POINTER_STICKY"
                })
        }
        "overflow" => {
            rt::print(format_args!("UART_INPUT_READY\n"));
            if rt::sleep(2000).is_err() || counters() != Some((4096, 0)) {
                return false;
            }
            let mut input = [0; 4096];
            if rt::read(0, &mut input) != Ok(4096) || !input.iter().all(|byte| *byte == b'X') {
                return false;
            }
            persist(b"OVERFLOW_4096") && emit(2, "result", "PASS") == 0
        }
        _ => false,
    }
}
fn main(_arguments: &[&[u8]]) -> i32 {
    let valid = run();
    if !valid {
        let _ = persist(b"FAIL");
    }
    let _ = rt::shutdown();
    if valid { 0 } else { 1 }
}
