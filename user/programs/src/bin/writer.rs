#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn work() -> rt::Result<()> {
    let fd = rt::open(b"/writer-test", 3 | 0x100 | 0x400)?;
    let result = (|| {
        let message = b"durable writer worker";
        rt::write_all(fd, message).map_err(|e| e.error)?;
        rt::seek(fd, 0)?;
        let mut bytes = [0; 64];
        let n = rt::read(fd, &mut bytes)?;
        if &bytes[..n] != message {
            return Err(-5);
        }
        Ok(())
    })();
    let closed = rt::close(fd);
    result.and(closed)
}
fn main(_: &[&[u8]]) -> i32 {
    match work() {
        Ok(()) => {
            rt::println!("writer verified durable bytes");
            0
        }
        Err(e) => {
            rt::println!("writer error {}", e);
            1
        }
    }
}
