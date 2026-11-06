#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);

fn raw(call: u64, args: [u64; 6]) -> i64 {
    // SAFETY: hostile boundary tests intentionally pass invalid user ranges to
    // the kernel. Valid mutable output regions are exclusively owned here.
    unsafe { rt::raw(call, args) }
}
fn check(condition: bool, id: u32, count: &mut u32) -> core::result::Result<(), u32> {
    if !condition {
        return Err(id);
    }
    *count += 1;
    Ok(())
}
fn work(count: &mut u32) -> core::result::Result<(), u32> {
    check(rt::abi_info() == Ok(rt::abi::abi_info()), 1, count)?;
    check(raw(u64::MAX, [0; 6]) == -38, 2, count)?;
    check(raw(2, [0, 0, 0, 0, 0, 1]) == -22, 3, count)?;
    check(raw(23, [0; 6]) == -1, 4, count)?;
    check(raw(0x4b544553, [0; 6]) < 0, 5, count)?;
    check(raw(13, [255, u64::MAX, 0, 0, 0, 0]) == -9, 6, count)?;
    check(raw(13, [1, u64::MAX, 0, 0, 0, 0]) == 0, 7, count)?;
    check(raw(13, [1, u64::MAX, 4097, 0, 0, 0]) == -22, 8, count)?;
    let base = rt::page_alloc(1).map_err(|_| 9u32)?;
    // SAFETY: successful page_alloc returns an exclusive, zeroed user allocation.
    let zero = unsafe { core::slice::from_raw_parts(base as *const u8, 4096) };
    check(zero.iter().all(|b| *b == 0), 10, count)?;
    check(raw(7, [base + 1, 1, 0, 0, 0, 0]) == -22, 11, count)?;
    check(raw(20, [base + 4092, 0, 0, 0, 0, 0]) == -14, 12, count)?;
    let lowest = rt::dup(1).map_err(|_| 13u32)?;
    check(lowest == 0, 14, count)?;
    rt::close(lowest).map_err(|_| 15u32)?;
    let ends = rt::pipe().map_err(|_| 16u32)?;
    check(rt::write(ends[1], b"unchanged bytes") == Ok(15), 17, count)?;
    check(
        raw(12, [ends[0] as u64, base + 4088, 15, 0, 0, 0]) == -14,
        18,
        count,
    )?;
    let mut buffer = [0u8; 64];
    check(
        rt::read(ends[0], &mut buffer) == Ok(15) && &buffer[..15] == b"unchanged bytes",
        19,
        count,
    )?;
    rt::close(ends[0]).map_err(|_| 20u32)?;
    check(rt::write(ends[1], b"x") == Err(-32), 21, count)?;
    rt::close(ends[1]).map_err(|_| 22u32)?;
    // SAFETY: no borrowed slice of the allocation is used after this point.
    unsafe { rt::page_free(base, 1) }.map_err(|_| 23u32)?;
    check(raw(0, [base, 0, 0, 0, 0, 0]) == -14, 24, count)?;
    let reused = rt::page_alloc(1).map_err(|_| 25u32)?;
    check(reused == base, 26, count)?;
    unsafe { rt::page_free(reused, 1) }.map_err(|_| 27u32)?;
    let start = rt::clock().map_err(|_| 28u32)?;
    rt::sleep(2).map_err(|_| 29u32)?;
    check(
        rt::clock().map_err(|_| 30u32)? >= start + 2_000_000,
        31,
        count,
    )?;
    rt::yield_now().map_err(|_| 32u32)?;

    let fd = rt::open(b"/abi-test", 3 | 0x100 | 0x400).map_err(|_| 33u32)?;
    check(rt::write(fd, b"abcdefgh") == Ok(8), 34, count)?;
    let alias = rt::dup(fd).map_err(|_| 35u32)?;
    check(rt::seek(alias, 0) == Ok(0), 36, count)?;
    check(
        rt::read(fd, &mut buffer[..3]) == Ok(3) && &buffer[..3] == b"abc",
        37,
        count,
    )?;
    check(
        rt::read(alias, &mut buffer[..3]) == Ok(3) && &buffer[..3] == b"def",
        38,
        count,
    )?;
    let independent = rt::open(b"/abi-test", 1).map_err(|_| 39u32)?;
    check(
        rt::read(independent, &mut buffer[..3]) == Ok(3) && &buffer[..3] == b"abc",
        40,
        count,
    )?;
    check(rt::unlink(b"/abi-test") == Err(-16), 41, count)?;
    check(rt::seek(fd, 9) == Err(-22), 42, count)?;
    check(rt::fsync(fd) == Ok(()), 43, count)?;
    for d in [fd, alias, independent] {
        rt::close(d).map_err(|_| 44u32)?;
    }
    check(rt::close(fd) == Err(-9), 45, count)?;
    rt::rename(b"/abi-test", b"/abi-renamed").map_err(|_| 46u32)?;
    check(rt::stat(b"/abi-test") == Err(-2), 47, count)?;
    rt::unlink(b"/abi-renamed").map_err(|_| 48u32)?;
    let child = rt::spawn(b"/fault", &[], [-1, 1, 2]).map_err(|_| 49u32)?;
    check(raw(9, [child, u64::MAX, 0, 0, 0, 0]) == -14, 50, count)?;
    let status = rt::wait(child, false).map_err(|_| 51u32)?;
    check(status.kind == 1 && status.fault_address == 0, 52, count)?;
    check(rt::wait(child, false) == Err(-10), 53, count)?;
    check(raw(6, [0; 6]) == -22, 54, count)?;
    check(raw(4, [60001, 0, 0, 0, 0, 0]) == -22, 55, count)?;
    Ok(())
}
fn main(_: &[&[u8]]) -> i32 {
    let mut count = 0;
    match work(&mut count) {
        Ok(()) => {
            rt::println!("selftest completed checks={}", count);
            0
        }
        Err(id) => {
            rt::println!("selftest failed assertion={} after={}", id, count);
            1
        }
    }
}
