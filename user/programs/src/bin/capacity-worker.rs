#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn command() -> rt::Result<()> {
    let mut byte = [0];
    if rt::read(0, &mut byte)? == 1 && byte[0] == 1 {
        Ok(())
    } else {
        Err(-5)
    }
}
fn run(mode: &[u8]) -> rt::Result<()> {
    command()?;
    let pid = rt::getpid()?;
    let mut entries = [[0; 32]; 64];
    let n = rt::process_list(&mut entries)?;
    let initial = entries[..n]
        .iter()
        .find(|e| u64::from_le_bytes(e[..8].try_into().unwrap()) == pid)
        .map(|e| u32::from_le_bytes(e[20..24].try_into().unwrap()) as u64)
        .ok_or(-5)?;
    let mut count = 0u64;
    let error = if mode == b"memory" {
        while rt::page_alloc(256).is_ok() {
            count += 256;
        }
        loop {
            match rt::page_alloc(1) {
                Ok(_) => count += 1,
                Err(error) => break error,
            }
        }
    } else if mode == b"files" {
        loop {
            match rt::open(b"/capacity-file", 1) {
                Ok(_) => count += 1,
                Err(error) => break error,
            }
        }
    } else if mode == b"pipes" {
        loop {
            match rt::pipe() {
                Ok(_) => count += 1,
                Err(error) => break error,
            }
        }
    } else {
        return Err(-22);
    };
    let mut report = [0; 32];
    for (i, value) in [count, error as u64, initial, 4096 - initial]
        .into_iter()
        .enumerate()
    {
        report[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    rt::write_all(1, &report).map_err(|e| e.error)?;
    command()?;
    // All deliberately retained resources are reclaimed by exit, not by the test.
    Ok(())
}
fn main(args: &[&[u8]]) -> i32 {
    if args.len() == 1 && run(args[0]).is_ok() {
        0
    } else {
        1
    }
}
