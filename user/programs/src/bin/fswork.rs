#![no_std]
#![no_main]
//! One deterministic storage operation per invocation for the independent host
//! history oracle. No test-only kernel privilege or syscall is used.
use user_runtime as rt;
rt::entry!(main);
fn number(bytes: &[u8]) -> rt::Result<u64> {
    if bytes.is_empty() {
        return Err(-22);
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(-22);
        }
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(*byte - b'0')))
            .ok_or(-22)?;
    }
    Ok(value)
}
fn operation(args: &[&[u8]]) -> rt::Result<()> {
    match args {
        [b"create", path] => {
            let fd = rt::open(path, 2 | 0x100 | 0x200)?;
            rt::close(fd)
        }
        [b"truncate", path] => {
            let fd = rt::open(path, 2 | 0x400)?;
            rt::close(fd)
        }
        [b"unlink", path] => rt::unlink(path),
        [b"rename", old, new] => rt::rename(old, new),
        [b"write", path, offset, length, value] => {
            let offset = number(offset)?;
            let length = usize::try_from(number(length)?).map_err(|_| -22)?;
            let value = number(value)?;
            if length > 4096 || value > 255 {
                return Err(-22);
            }
            let mut data = [0u8; 4096];
            for (i, byte) in data[..length].iter_mut().enumerate() {
                *byte = (value as u8).wrapping_add((i % 251) as u8);
            }
            let fd = rt::open(path, 3)?;
            let result = (|| {
                rt::seek(fd, offset)?;
                if rt::write(fd, &data[..length])? != length {
                    return Err(-5);
                }
                Ok(())
            })();
            let closed = rt::close(fd);
            result.and(closed)
        }
        [b"read", path, offset, length, expected] => {
            let offset = number(offset)?;
            let length = usize::try_from(number(length)?).map_err(|_| -22)?;
            let expected = number(expected)?;
            if length > 4096 {
                return Err(-22);
            }
            let fd = rt::open(path, 1)?;
            let result = (|| {
                rt::seek(fd, offset)?;
                let mut data = [0u8; 4096];
                let size = rt::read(fd, &mut data[..length])?;
                if size != length {
                    return Err(-5);
                }
                let mut hash = 0xcbf29ce484222325u64;
                for byte in &data[..size] {
                    hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
                }
                if hash != expected {
                    return Err(-5);
                }
                Ok(())
            })();
            let closed = rt::close(fd);
            result.and(closed)
        }
        _ => Err(-22),
    }
}
fn main(args: &[&[u8]]) -> i32 {
    match operation(args) {
        Ok(()) => {
            rt::println!("FSWORK OK");
            0
        }
        Err(error) => {
            rt::println!("FSWORK ERROR {}", error);
            1
        }
    }
}
