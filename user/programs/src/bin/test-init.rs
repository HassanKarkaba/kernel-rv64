#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn emit(record: &[u8]) {
    // SAFETY: the immutable init owns this bounded immutable JSON buffer; the
    // private call exists only in the separately identified instrumented kernel.
    let value = unsafe {
        rt::raw(
            0x4b544553,
            [record.as_ptr() as u64, record.len() as u64, 0, 0, 0, 0],
        )
    };
    if value != 0 {
        rt::exit(127);
    }
}
fn child_check(path: &[u8]) -> rt::Result<bool> {
    let pipe = rt::pipe()?;
    let child = rt::spawn(path, &[], [-1, pipe[1] as i32, pipe[1] as i32]);
    rt::close(pipe[1])?;
    let child = match child {
        Ok(pid) => pid,
        Err(e) => {
            let _ = rt::close(pipe[0]);
            return Err(e);
        }
    };
    let mut output = [0u8; 4096];
    let mut length = 0;
    let mut truncated = false;
    loop {
        let mut bytes = [0u8; 256];
        let n = rt::read(pipe[0], &mut bytes)?;
        if n == 0 {
            break;
        }
        let retained = (output.len() - length).min(n);
        output[length..length + retained].copy_from_slice(&bytes[..retained]);
        length += retained;
        if retained != n {
            truncated = true;
        }
    }
    rt::close(pipe[0])?;
    let status = rt::wait(child, false)?;
    // Child text is never parsed as a protocol record; instrumented console
    // escaping makes even malicious KTEST strings nonauthoritative UOUT data.
    if length > 0 {
        let _ = rt::write_all(1, &output[..length]);
    }
    Ok(status.kind == 0 && status.code == 0 && !truncated)
}
fn main(_: &[&[u8]]) -> i32 {
    emit(
        concat!(
            r#"{"schema":1,"run_id":""#,
            env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#,
            env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"start","case_id":"guest-selftest","sequence":1}"#
        )
        .as_bytes(),
    );
    match child_check(b"/selftest").and_then(|first|if first{child_check(b"/boundaries")}else{Ok(false)}) {
        Ok(true) => emit(concat!(
            r#"{"schema":1,"run_id":""#, env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#, env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"result","case_id":"guest-selftest","sequence":2,"result":"PASS","child_kind":0,"child_code":0}"#
        ).as_bytes()),
        _ => emit(concat!(
            r#"{"schema":1,"run_id":""#, env!("KERNEL_TEST_RUN_ID"),
            r#"","boot_id":""#, env!("KERNEL_TEST_BOOT_ID"),
            r#"","event":"result","case_id":"guest-selftest","sequence":2,"result":"FAIL"}"#
        ).as_bytes()),
    }
    let _ = rt::shutdown();
    127
}
