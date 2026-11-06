#![no_std]
#![no_main]
//! Immutable init exercising shutdown drain and admission through the ordinary syscall ABI.
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
        write!(&mut text,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"shutdown-drain\",\"sequence\":{},\"event\":\"{}\"",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),self.sequence,event).unwrap();
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
            let _ = rt::write_all(1, b"SDTEST ");
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
fn read_byte(fd: u32, expected: u8) -> rt::Result<()> {
    let mut b = [0];
    if rt::read(fd, &mut b)? != 1 || b[0] != expected {
        return Err(-5);
    }
    Ok(())
}
fn spawn(role: &[u8], file: i32) -> rt::Result<(u64, u32, u32)> {
    let gate = rt::pipe()?;
    let reply = rt::pipe()?;
    let pid = rt::spawn(
        b"/shutdown-worker",
        &[role],
        [gate[0] as i32, reply[1] as i32, file],
    )?;
    rt::close(gate[0])?;
    rt::close(reply[1])?;
    read_byte(reply[0], b'S')?;
    Ok((pid, gate[1], reply[0]))
}
fn blocked(pid: u64) -> rt::Result<()> {
    for _ in 0..1000 {
        let mut records = [[0u8; 32]; 4];
        let count = rt::process_list(&mut records)?;
        for record in &records[..count] {
            if u64::from_le_bytes(record[..8].try_into().unwrap()) == pid
                && u32::from_le_bytes(record[16..20].try_into().unwrap()) == 3
            {
                return Ok(());
            }
        }
        rt::sleep(1)?;
    }
    Err(-5)
}
fn trace_dump(test: &mut Test, enabled: bool) -> rt::Result<()> {
    if !enabled {
        test.emit("trace-unavailable", format_args!(""));
        return Ok(());
    }
    // SAFETY: init exclusively controls this observation-only trace interface.
    if unsafe { rt::raw(0x4b545243, [1, 0, 0, 0, 0, 0]) } != 0 {
        return Err(-5);
    }
    let mut header = [0u8; 32];
    // SAFETY: all output pointers below cover initialized live arrays.
    if unsafe { rt::raw(0x4b545243, [2, header.as_mut_ptr() as u64, 0, 0, 0, 0]) } != 0 {
        return Err(-5);
    }
    let count = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let lost = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let frequency = u64::from_le_bytes(header[24..32].try_into().unwrap());
    if count > 8192 || lost != 0 {
        return Err(-5);
    }
    test.emit(
        "trace-header",
        format_args!(
            ",\"count\":{},\"lost\":{},\"frequency\":{}",
            count, lost, frequency
        ),
    );
    let mut offset = 0;
    while offset < count {
        let n = (count - offset).min(32);
        let mut bytes = [0u8; 1280];
        // SAFETY: the bounded request fits this complete owned output array.
        if unsafe { rt::raw(0x4b545243, [3, bytes.as_mut_ptr() as u64, n, offset, 0, 0]) }
            != n as i64
        {
            return Err(-5);
        }
        for index in 0..n as usize {
            let row: [u64; 5] = core::array::from_fn(|i| {
                u64::from_le_bytes(
                    bytes[index * 40 + i * 8..index * 40 + i * 8 + 8]
                        .try_into()
                        .unwrap(),
                )
            });
            test.emit("trace", format_args!(",\"record\":{:?}", row));
        }
        offset += n;
    }
    Ok(())
}
fn run(test: &mut Test, mode: u8) -> rt::Result<()> {
    let ack = rt::open(b"/ack", 3)?;
    if rt::write(ack, b"K")? != 1 {
        return Err(-5);
    }
    rt::close(ack)?;
    test.emit(
        "acknowledged",
        format_args!(",\"bytes\":1,\"clock_ns\":{}", rt::clock()?),
    );
    let active = rt::open(b"/active", 3)?;
    let waiter_file = rt::open(b"/waiter", 3)?;
    let writer = spawn(b"writer", active as i32)?;
    rt::close(active)?;
    let waiter = spawn(b"waiter", waiter_file as i32)?;
    rt::close(waiter_file)?;
    let peer = spawn(b"peer", -1)?;
    test.emit(
        "participants",
        format_args!(
            ",\"writer\":{},\"waiter\":{},\"peer\":{},\"unauthorized_shutdown_denials\":3",
            writer.0, waiter.0, peer.0
        ),
    );
    let owners = census()?;
    test.counts("active_children", owners);
    // SAFETY: private trace start takes no pointers; release returns ENOSYS.
    let trace = unsafe { rt::raw(0x4b545243, [0, 0, 0, 0, 0, 0]) };
    if trace != 0 && trace != -38 {
        return Err(trace);
    }
    test.phase("arm_active")?;
    rt::write(writer.1, b"g")?;
    read_byte(writer.2, b'R')?;
    test.phase("active_submitted")?;
    rt::write(waiter.1, b"g")?;
    read_byte(waiter.2, b'R')?;
    blocked(waiter.0)?;
    rt::write(peer.1, b"g")?;
    read_byte(peer.2, b'P')?;
    test.emit(
        "peer_progress",
        format_args!(",\"pipe_bytes\":1,\"compute_iterations\":100000"),
    );
    trace_dump(test, trace == 0)?;
    if mode == b'W' {
        // SAFETY: init-only declared observer parks init after flag publication;
        // it does not bypass any admission rule or mutate filesystem state.
        let result = unsafe { rt::raw(0x4b54494c, [5, 0, 0, 0, 0, 0]) };
        if result != 0 {
            return Err(result);
        }
    }
    test.phase("shutdown_ready")?;
    test.emit(
        "request",
        format_args!(
            ",\"clock_ns\":{},\"observer\":{}",
            rt::clock()?,
            mode == b'W'
        ),
    );
    rt::shutdown()?;
    Err(-5)
}
fn main(_: &[&[u8]]) -> i32 {
    let mut test = Test {
        sequence: 0,
        pass: true,
    };
    test.emit("start", format_args!(""));
    let mut mode = [0];
    let result = rt::read(0, &mut mode).and_then(|n| {
        if n == 1 && matches!(mode[0], b'C' | b'W' | b'D') {
            run(&mut test, mode[0])
        } else {
            Err(-22)
        }
    });
    test.check("unexpected_shutdown_return", status(result), 0);
    let _ = rt::shutdown();
    1
}
