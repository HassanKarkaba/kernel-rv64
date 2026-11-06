#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut total = 0;
    let mut bytes = [0; 1024];
    loop {
        match rt::read(0, &mut bytes) {
            Ok(0) => break,
            Ok(n) => {
                for (i, byte) in bytes[..n].iter().enumerate() {
                    if *byte != ((total + i) % 1024 % 251) as u8 {
                        return 2;
                    }
                }
                total += n;
            }
            Err(_) => return 1,
        }
    }
    if total != 8192 {
        return 3;
    }
    rt::println!("consumer verified 8192 bytes");
    0
}
