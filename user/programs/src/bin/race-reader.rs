#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn exchange() -> rt::Result<bool> {
    let pair = rt::pipe()?;
    let child = rt::spawn(b"/race-writer", &[], [-1, pair[1] as i32, -1])?;
    rt::close(pair[1])?;
    let mut byte = [0];
    let count = rt::read(pair[0], &mut byte)?;
    rt::close(pair[0])?;
    let status = rt::wait(child, false)?;
    Ok(count == 1 && byte[0] == 0x5a && status.kind == 0 && status.code == 0)
}
fn main(_: &[&[u8]]) -> i32 {
    if matches!(exchange(), Ok(true)) { 0 } else { 1 }
}
