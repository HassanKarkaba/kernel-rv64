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
    let case = if env!("KERNEL_BENCH_KIND") == "fairness" {
        concat!("fairness-", env!("KERNEL_BENCH_PROCESSES"))
    } else {
        env!("KERNEL_BENCH_KIND")
    };
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
fn measure(sequence: &mut u64) -> rt::Result<bool> {
    let count = if env!("KERNEL_BENCH_PROCESSES") == "4" {
        4
    } else {
        8
    };
    let mut pids = [0u64; 8];
    for pid in &mut pids[..count] {
        *pid = rt::spawn(b"/bench-worker", &[], [-1, -1, -1])?;
    }
    rt::sleep(1000)?;
    // SAFETY: syscall copies the complete selected PID list synchronously.
    let reset = unsafe { rt::raw(0x4b544d45, [0, pids.as_ptr() as u64, count as u64, 0, 0, 0]) };
    if reset < 0 {
        return Err(reset);
    }
    rt::sleep(10_000)?;
    let mut snapshot = [0u8; 416];
    let n = unsafe { rt::raw(0x4b544d45, [1, snapshot.as_mut_ptr() as u64, 416, 0, 0, 0]) };
    if n < 0 {
        return Err(n);
    }
    let begin = u64_at(&snapshot, 8);
    let end = u64_at(&snapshot, 16);
    let frequency = u64_at(&snapshot, 24);
    let mut passed = n as usize == 32 + count * 48 && end - begin == frequency * 10;
    let mut total = 0u64;
    for i in 0..count {
        total += u64_at(&snapshot, 32 + i * 48 + 8);
    }
    passed &= total > 0;
    *sequence += 1;
    emit(
        *sequence,
        "window",
        format_args!(
            ",\"start_ticks\":{},\"end_ticks\":{},\"frequency\":{},\"user_ticks\":{}",
            begin, end, frequency, total
        ),
    );
    for i in 0..count {
        let record = &snapshot[32 + i * 48..32 + (i + 1) * 48];
        let ticks = u64_at(record, 8);
        let dispatches = u64_at(record, 16);
        let gap = u64_at(record, 24);
        let (low, high) = if count == 4 { (20, 30) } else { (10, 15) };
        passed &= u64_at(record, 0) == pids[i]
            && gap < count as u64
            && ticks * 100 >= total * low
            && ticks * 100 <= total * high
            && dispatches > 0;
        *sequence += 1;
        emit(
            *sequence,
            "worker",
            format_args!(
                ",\"pid\":{},\"user_ticks\":{},\"dispatches\":{},\"max_peer_gap\":{},\"first_ordinal\":{},\"last_ordinal\":{}",
                pids[i],
                ticks,
                dispatches,
                gap,
                u64_at(record, 32),
                u64_at(record, 40)
            ),
        );
    }
    let mut offset = 0usize;
    loop {
        let mut trace = [0u8; 4096];
        let n = unsafe {
            rt::raw(
                0x4b544d45,
                [2, trace.as_mut_ptr() as u64, 256, offset as u64, 0, 0],
            )
        };
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            break;
        }
        for i in 0..n as usize {
            *sequence += 1;
            emit(
                *sequence,
                "dispatch",
                format_args!(
                    ",\"ordinal\":{},\"pid\":{},\"ticks\":{}",
                    offset + i + 1,
                    u64_at(&trace, i * 16),
                    u64_at(&trace, i * 16 + 8)
                ),
            );
        }
        offset += n as usize;
    }
    Ok(passed)
}
fn main(_: &[&[u8]]) -> i32 {
    let mut sequence = 1;
    let kind = env!("KERNEL_BENCH_KIND");
    if kind == "fairness" {
        emit(
            sequence,
            "start",
            format_args!(",\"warmup_ms\":1000,\"sample_ms\":10000"),
        );
    } else {
        emit(sequence, "start", format_args!(",\"kind\":\"{}\"", kind));
    }
    let result = match kind {
        "fairness" => measure(&mut sequence),
        "wakeup" => wakeup(&mut sequence),
        "context" => context(&mut sequence),
        "masking" => masking(&mut sequence),
        "reclaim" => reclaim(&mut sequence),
        _ => Err(-22),
    };
    sequence += 1;
    match result {
        Ok(true) => emit(sequence, "result", format_args!(",\"result\":\"PASS\"")),
        Ok(false) => emit(sequence, "result", format_args!(",\"result\":\"FAIL\"")),
        Err(e) => emit(
            sequence,
            "result",
            format_args!(",\"result\":\"FAIL\",\"error\":{}", e),
        ),
    }
    let _ = rt::shutdown();
    127
}

fn metric(op: u64, pointer: u64, count: u64, offset: u64) -> rt::Result<u64> {
    // SAFETY: each caller owns any bounded byte buffers supplied here.
    let result = unsafe { rt::raw(0x4b544d45, [op, pointer, count, offset, 0, 0]) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}
fn frequency() -> rt::Result<u64> {
    let mut bytes = [0u8; 416];
    metric(1, bytes.as_mut_ptr() as u64, 416, 0)?;
    Ok(u64_at(&bytes, 24))
}
fn status_ok(pid: u64) -> rt::Result<bool> {
    let status = rt::wait(pid, false)?;
    Ok(status.kind == 0 && status.code == 0)
}
fn wakeup(sequence: &mut u64) -> rt::Result<bool> {
    let gate = rt::pipe()?;
    let sleeper = rt::spawn(b"/bench-sleeper", &[], [gate[0] as i32, -1, -1])?;
    rt::close(gate[0])?;
    for _ in 0..7 {
        rt::spawn(b"/bench-worker", &[], [-1, -1, -1])?;
    }
    metric(3, sleeper, 0, 0)?;
    rt::write_all(gate[1], b"s").map_err(|e| e.error)?;
    rt::close(gate[1])?;
    let mut passed = status_ok(sleeper)?;
    let frequency = frequency()?;
    *sequence += 1;
    emit(
        *sequence,
        "configuration",
        format_args!(
            ",\"frequency\":{},\"sleeper_pid\":{},\"peers\":7,\"sleep_ms\":10,\"required_samples\":10000",
            frequency, sleeper
        ),
    );
    let mut offset = 0usize;
    let mut over45 = 0;
    let mut maximum = 0u64;
    loop {
        let mut bytes = [0u8; 4096];
        let n = metric(4, bytes.as_mut_ptr() as u64, 128, offset as u64)? as usize;
        if n == 0 {
            break;
        }
        for i in 0..n {
            let record = &bytes[i * 32..i * 32 + 32];
            let deadline = u64_at(record, 0);
            let woken = u64_at(record, 8);
            let entered = u64_at(record, 16);
            let latency = u64_at(record, 24);
            passed &= deadline <= woken && woken <= entered && latency == entered - woken;
            if latency * 1000 > frequency * 45 {
                over45 += 1;
            }
            maximum = maximum.max(latency);
            *sequence += 1;
            emit(
                *sequence,
                "wake-sample",
                format_args!(
                    ",\"sample\":{},\"deadline_ticks\":{},\"wake_ticks\":{},\"user_ticks\":{},\"wake_latency_ticks\":{},\"deadline_latency_ticks\":{}",
                    offset + i + 1,
                    deadline,
                    woken,
                    entered,
                    latency,
                    entered.saturating_sub(deadline)
                ),
            );
        }
        offset += n;
    }
    Ok(passed && offset == 10000 && over45 <= 100 && maximum * 1000 <= frequency * 100)
}
fn context(sequence: &mut u64) -> rt::Result<bool> {
    for _ in 0..2 {
        rt::spawn(b"/bench-worker", &[], [-1, -1, -1])?;
    }
    rt::sleep(1000)?;
    metric(5, 0, 0, 0)?;
    rt::sleep(60_000)?;
    let frequency = frequency()?;
    *sequence += 1;
    emit(
        *sequence,
        "configuration",
        format_args!(
            ",\"frequency\":{},\"required_samples\":10000,\"calibration\":\"consecutive-counter-reads\",\"scope\":\"process-to-scheduler-to-process\"",
            frequency
        ),
    );
    let mut offset = 0;
    loop {
        let mut bytes = [0u8; 4096];
        let n = metric(6, bytes.as_mut_ptr() as u64, 256, offset)? as usize;
        if n == 0 {
            break;
        }
        for i in 0..n {
            *sequence += 1;
            emit(
                *sequence,
                "context-sample",
                format_args!(
                    ",\"sample\":{},\"ticks\":{},\"calibration_ticks\":{}",
                    offset + i as u64 + 1,
                    u64_at(&bytes, i * 16),
                    u64_at(&bytes, i * 16 + 8)
                ),
            );
        }
        offset += n as u64;
    }
    Ok(offset == 10000)
}
fn masking(sequence: &mut u64) -> rt::Result<bool> {
    metric(7, 0, 0, 0)?;
    let child = rt::spawn(b"/mask-worker", &[], [-1, -1, -1])?;
    let passed = status_ok(child)?;
    let mut bytes = [0u8; 256];
    metric(8, bytes.as_mut_ptr() as u64, 256, 0)?;
    let count = u64_at(&bytes, 8);
    let maximum = u64_at(&bytes, 16);
    let frequency = u64_at(&bytes, 24);
    let line = u32::from_le_bytes(bytes[88..92].try_into().unwrap());
    let n = u32::from_le_bytes(bytes[92..96].try_into().unwrap()) as usize;
    let label = core::str::from_utf8(&bytes[96..96 + n]).map_err(|_| -22)?;
    *sequence += 1;
    emit(
        *sequence,
        "masking",
        format_args!(
            ",\"frequency\":{},\"intervals\":{},\"maximum_ticks\":{},\"location\":\"{}\",\"line\":{},\"start_ticks\":{},\"end_ticks\":{}",
            frequency,
            count,
            maximum,
            label,
            line,
            u64_at(&bytes, 224),
            u64_at(&bytes, 232)
        ),
    );
    for i in 0..7 {
        *sequence += 1;
        emit(
            *sequence,
            "mask-bucket",
            format_args!(",\"bucket\":{},\"count\":{}", i, u64_at(&bytes, 32 + i * 8)),
        );
    }
    Ok(passed && count > 0 && maximum * 1000 <= frequency)
}
fn ownership() -> rt::Result<[u64; 12]> {
    let mut bytes = [0u8; 128];
    metric(9, bytes.as_mut_ptr() as u64, 128, 0)?;
    let mut counts = [0; 12];
    for (i, value) in counts.iter_mut().enumerate() {
        *value = u64_at(&bytes, 8 + i * 8);
    }
    Ok(counts)
}
fn census(sequence: &mut u64, event: &str, counts: &[u64; 12]) {
    for (index, value) in counts.iter().enumerate() {
        *sequence += 1;
        emit(
            *sequence,
            event,
            format_args!(",\"owner\":{},\"count\":{}", index, value),
        );
    }
}
fn reclaim(sequence: &mut u64) -> rt::Result<bool> {
    let before = ownership()?;
    census(sequence, "baseline", &before);
    for iteration in 1..=10_000 {
        let child = rt::spawn(b"/reclaim-child", &[], [-1, -1, -1])?;
        if !status_ok(child)? {
            return Ok(false);
        }
        if iteration % 1000 == 0 {
            *sequence += 1;
            emit(
                *sequence,
                "progress",
                format_args!(",\"completed_cycles\":{}", iteration),
            );
        }
    }
    let after = ownership()?;
    census(sequence, "final", &after);
    Ok(before == after)
}
