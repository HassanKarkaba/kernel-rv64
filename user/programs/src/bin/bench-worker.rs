#![no_std]
#![no_main]
user_runtime::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut value = 1u64;
    loop {
        value = core::hint::black_box(
            value
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407),
        );
    }
}
