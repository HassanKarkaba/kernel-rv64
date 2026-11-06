#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn work() -> rt::Result<()> {
    for _ in 0..1000 {
        let base = rt::page_alloc(1)?;
        // SAFETY: no references to this fresh page were created.
        unsafe { rt::page_free(base, 1) }?;
        let pair = rt::pipe()?;
        rt::write_all(pair[1], &[0x55; 512]).map_err(|e| e.error)?;
        let mut out = [0u8; 512];
        if rt::read(pair[0], &mut out)? != 512 || out != [0x55; 512] {
            return Err(-5);
        }
        rt::close(pair[0])?;
        rt::close(pair[1])?;
        rt::yield_now()?;
    }
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    if work().is_ok() { 0 } else { 1 }
}
