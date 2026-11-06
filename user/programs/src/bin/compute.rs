#![no_std]
#![no_main]
user_runtime::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut value = 1u64;
    for i in 0..2_000_000u64 {
        value = core::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(i));
    }
    user_runtime::println!("compute completed {}", value);
    0
}
