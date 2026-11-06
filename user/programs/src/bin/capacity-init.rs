#![no_std]
#![no_main]
use core::fmt::{self, Write};
use user_runtime as rt;
rt::entry!(main);
struct Json {
    bytes: [u8; 512],
    length: usize,
}
impl Write for Json {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() > self.bytes.len() - self.length {
            return Err(fmt::Error);
        }
        self.bytes[self.length..self.length + s.len()].copy_from_slice(s.as_bytes());
        self.length += s.len();
        Ok(())
    }
}
fn emit(sequence: &mut u64, event: &str, fields: fmt::Arguments<'_>) {
    *sequence += 1;
    let mut out = Json {
        bytes: [0; 512],
        length: 0,
    };
    write!(&mut out,"{{\"schema\":1,\"run_id\":\"{}\",\"boot_id\":\"{}\",\"case_id\":\"global-capacity\",\"sequence\":{},\"event\":\"{}\"",env!("KERNEL_TEST_RUN_ID"),env!("KERNEL_TEST_BOOT_ID"),sequence,event).unwrap();
    out.write_fmt(fields).unwrap();
    out.write_str("}").unwrap();
    // SAFETY: immutable init owns this initialized bounded JSON buffer.
    if unsafe {
        rt::raw(
            0x4b544553,
            [out.bytes.as_ptr() as u64, out.length as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        rt::exit(127)
    }
}
fn census() -> rt::Result<[u64; 12]> {
    let mut wire = [0u8; 128];
    // SAFETY: init owns the full writable output and the private call copies synchronously.
    let n = unsafe { rt::raw(0x4b544d45, [9, wire.as_mut_ptr() as u64, 128, 0, 0, 0]) };
    if n != 128 {
        return Err(if n < 0 { n } else { -5 });
    }
    let mut out = [0; 12];
    for (i, value) in out.iter_mut().enumerate() {
        *value = u64::from_le_bytes(wire[8 + i * 8..16 + i * 8].try_into().unwrap());
    }
    Ok(out)
}
fn census_emit(sequence: &mut u64, kind: &str, event: &str, values: &[u64; 12]) {
    for (i, value) in values.iter().enumerate() {
        emit(
            sequence,
            event,
            format_args!(",\"kind\":\"{}\",\"owner\":{},\"count\":{}", kind, i, value),
        );
    }
}
fn read_report(fd: u32) -> rt::Result<[u64; 4]> {
    let mut wire = [0; 32];
    let mut done = 0;
    while done < wire.len() {
        let n = rt::read(fd, &mut wire[done..])?;
        if n == 0 {
            return Err(-5);
        }
        done += n;
    }
    Ok(core::array::from_fn(|i| {
        u64::from_le_bytes(wire[i * 8..i * 8 + 8].try_into().unwrap())
    }))
}
fn pool() -> rt::Result<[u64; 4]> {
    let mut wire = [0u8; 32];
    // SAFETY: init owns the complete writable private-observation output.
    let n = unsafe { rt::raw(0x4b544d45, [10, wire.as_mut_ptr() as u64, 32, 0, 0, 0]) };
    if n != 32 {
        return Err(if n < 0 { n } else { -5 });
    }
    Ok(core::array::from_fn(|i| {
        u64::from_le_bytes(wire[i * 8..i * 8 + 8].try_into().unwrap())
    }))
}
fn family(sequence: &mut u64, kind: &str) -> rt::Result<bool> {
    let baseline = census()?;
    census_emit(sequence, kind, "baseline", &baseline);
    let mut children = [0u64; 9];
    let mut gates = [0u32; 9];
    let mut replies = [0u32; 9];
    for i in 0..9 {
        let gate = rt::pipe()?;
        let reply = rt::pipe()?;
        children[i] = rt::spawn(
            b"/capacity-worker",
            &[kind.as_bytes()],
            [gate[0] as i32, reply[1] as i32, -1],
        )?;
        rt::close(gate[0])?;
        rt::close(reply[1])?;
        gates[i] = gate[1];
        replies[i] = reply[0];
    }
    let mut pass = true;
    let mut total = 0;
    let mut constrained = false;
    for i in 0..9 {
        rt::write_all(gates[i], &[1]).map_err(|e| e.error)?;
        let report = read_report(replies[i])?;
        let count = report[0];
        let error = report[1] as i64;
        total += count;
        match kind {
            "memory" => {
                pass &= error == -12 && count <= report[3];
                constrained |= count < report[3];
            }
            "files" => pass &= matches!(error, -23 | -24) && count <= 30,
            "pipes" => pass &= matches!(error, -23 | -24) && count <= 15,
            _ => return Err(-22),
        }
        emit(
            sequence,
            "worker",
            format_args!(
                ",\"kind\":\"{}\",\"worker\":{},\"pid\":{},\"allocated\":{},\"error\":{},\"initial_pages\":{},\"page_allowance\":{}",
                kind, i, children[i], count, error, report[2], report[3]
            ),
        );
    }
    let peak = census()?;
    census_emit(sequence, kind, "peak", &peak);
    pass &= match kind {
        "memory" => {
            let physical = pool()?;
            emit(
                sequence,
                "pool",
                format_args!(
                    ",\"total\":{},\"reserved\":{},\"live\":{},\"free\":{}",
                    physical[0], physical[1], physical[2], physical[3]
                ),
            );
            physical[0] == 32768
                && physical[1] + physical[2] == physical[0]
                && physical[3] == 0
                && peak[0] == physical[2]
                && constrained
        }
        "files" => peak[7] == 256 && total == 256,
        "pipes" => peak[9] == 64 && total == 46,
        _ => false,
    };
    for gate in gates {
        rt::write_all(gate, &[1]).map_err(|e| e.error)?;
        rt::close(gate)?;
    }
    for i in 0..9 {
        let status = rt::wait(children[i], false)?;
        pass &= status.kind == 0 && status.code == 0;
        rt::close(replies[i])?;
    }
    let final_counts = census()?;
    census_emit(sequence, kind, "final", &final_counts);
    pass &= baseline == final_counts;
    match kind {
        "memory" => {
            let page = rt::page_alloc(1)?;
            // SAFETY: this exact fresh allocation has no outstanding references.
            unsafe {
                rt::page_free(page, 1)?;
            }
        }
        "files" => {
            let fd = rt::open(b"/capacity-file", 1)?;
            rt::close(fd)?;
        }
        "pipes" => {
            let pair = rt::pipe()?;
            rt::close(pair[0])?;
            rt::close(pair[1])?;
        }
        _ => return Err(-22),
    }
    pass &= census()? == baseline;
    emit(
        sequence,
        "family-result",
        format_args!(
            ",\"kind\":\"{}\",\"result\":\"{}\",\"retry\":true",
            kind,
            if pass { "PASS" } else { "FAIL" }
        ),
    );
    Ok(pass)
}
fn run(sequence: &mut u64) -> rt::Result<bool> {
    let file = rt::open(b"/capacity-file", 0x303)?;
    rt::close(file)?;
    let mut pass = true;
    for kind in ["memory", "files", "pipes"] {
        pass &= family(sequence, kind)?;
    }
    rt::unlink(b"/capacity-file")?;
    Ok(pass)
}
fn main(_: &[&[u8]]) -> i32 {
    let mut sequence = 0;
    emit(&mut sequence, "start", format_args!(""));
    let result = run(&mut sequence);
    emit(
        &mut sequence,
        "result",
        format_args!(
            ",\"result\":\"{}\",\"error\":{}",
            if matches!(result, Ok(true)) {
                "PASS"
            } else {
                "FAIL"
            },
            result.err().unwrap_or(0)
        ),
    );
    let _ = rt::shutdown();
    127
}
