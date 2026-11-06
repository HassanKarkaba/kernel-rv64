#![no_std]
#![no_main]
//! Storage-failure containment through the ordinary release syscall ABI.
use user_runtime as rt;
rt::entry!(main);
fn check() -> rt::Result<()> {
    let fd = rt::open(b"/payload", 1)?;
    rt::println!("FSFAIL ARMED");
    let mut signal = [0u8; 1];
    if rt::read(0, &mut signal)? != 1 {
        return Err(-5);
    }
    let mut data = [0u8; 4096];
    if rt::read(fd, &mut data) != Err(-5) {
        return Err(-5);
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
    if rt::write(pipe[1], b"survived")? != 8 {
        return Err(-5);
    }
    if rt::read(pipe[0], &mut data[..8])? != 8 || &data[..8] != b"survived" {
        return Err(-5);
    }
    rt::close(pipe[0])?;
    rt::close(pipe[1])?;
    let allocation = rt::page_alloc(1)?;
    // SAFETY: this process owns this exact new allocation and created no aliases.
    unsafe {
        rt::page_free(allocation, 1)?;
    }
    rt::println!("FSFAIL CONTAINED");
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    match check() {
        Ok(()) => 0,
        Err(error) => {
            rt::println!("FSFAIL ERROR {}", error);
            1
        }
    }
}
