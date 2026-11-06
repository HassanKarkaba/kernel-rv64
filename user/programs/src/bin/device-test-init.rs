#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn emit(end: bool, passed: bool) {
    let record: &[u8] = if !end {
        concat!(
            r#"{"schema":1,"run_id":""#,
            env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#,
            env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"start","case_id":"device-fault","sequence":1}"#
        )
        .as_bytes()
    } else if passed {
        concat!(
            r#"{"schema":1,"run_id":""#,
            env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#,
            env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"result","case_id":"device-fault","sequence":2,"result":"PASS"}"#
        )
        .as_bytes()
    } else {
        concat!(
            r#"{"schema":1,"run_id":""#,
            env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#,
            env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"result","case_id":"device-fault","sequence":2,"result":"FAIL"}"#
        )
        .as_bytes()
    };
    // SAFETY: this immutable init owns the entire record during the private call.
    if unsafe {
        rt::raw(
            0x4b544553,
            [record.as_ptr() as u64, record.len() as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        rt::exit(127)
    }
}
fn work() -> rt::Result<()> {
    let mode = u64::from(env!("KERNEL_DEVICE_FAULT").as_bytes()[0] - b'0');
    let fd = rt::open(b"/payload", 1)?;
    let peer = rt::spawn(b"/fault-probe", &[b"sleep"], [-1, -1, -1])?;
    let start = rt::clock()?;
    // SAFETY: scalar-only test hook is limited to immutable init in instrumented builds.
    if unsafe { rt::raw(0x4b544649, [mode, 0, 0, 0, 0, 0]) } != 0 {
        return Err(-5);
    }
    let mut data = [0u8; 4096];
    if rt::read(fd, &mut data) != Err(-5) {
        return Err(-5);
    }
    if mode >= 6 {
        if rt::clock()?.saturating_sub(start) < 5_000_000_000 {
            return Err(-5);
        }
        let status = rt::wait(peer, true)?;
        if status.kind != 0 || status.code != 0 {
            return Err(-5);
        }
    } else {
        let status = rt::wait(peer, false)?;
        if status.kind != 0 || status.code != 0 {
            return Err(-5);
        }
    }
    if rt::read(fd, &mut data[..1]) != Err(-5)
        || rt::open(b"/payload", 1) != Err(-5)
        || rt::fsync(fd) != Err(-5)
        || rt::stat(b"/payload") != Err(-5)
    {
        return Err(-5);
    }
    if rt::read(fd, &mut []) != Ok(0) {
        return Err(-5);
    }
    rt::close(fd)?;
    let pipe = rt::pipe()?;
    if rt::write(pipe[1], b"survived")? != 8
        || rt::read(pipe[0], &mut data[..8])? != 8
        || &data[..8] != b"survived"
    {
        return Err(-5);
    }
    rt::close(pipe[0])?;
    rt::close(pipe[1])?;
    let page = rt::page_alloc(1)?;
    // SAFETY: this exact allocation has no live references.
    unsafe {
        rt::page_free(page, 1)?;
    }
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    emit(false, false);
    emit(true, work().is_ok());
    let _ = rt::shutdown();
    127
}
