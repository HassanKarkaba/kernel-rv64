//! QEMU11.1.3 synthetic virt/one-hart/256MiB DTB, rng-seed replaced by zeros.
use kernel_platform::dtb::{self, Error};
const GOOD: &[u8] = include_bytes!("fixtures/virt-qemu-11.1.3.dtb");
fn property(bytes: &[u8], wanted: &[u8], node: Option<&[u8]>) -> (usize, usize) {
    let mut nodes = Vec::new();
    let u32at = |p| u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
    let mut at = u32at(8);
    let strings = u32at(12);
    loop {
        let token = u32at(at);
        at += 4;
        match token {
            1 => {
                let end = at + bytes[at..].iter().position(|b| *b == 0).unwrap();
                nodes.push(&bytes[at..end]);
                at = (end + 4) & !3;
            }
            2 => {
                nodes.pop();
            }
            4 => {}
            3 => {
                let n = u32at(at);
                let s = strings + u32at(at + 4);
                at += 8;
                let e = s + bytes[s..].iter().position(|b| *b == 0).unwrap();
                if &bytes[s..e] == wanted && node.is_none_or(|name| nodes.last() == Some(&name)) {
                    return (at, n);
                }
                at = (at + n + 3) & !3;
            }
            _ => panic!("missing fixture property"),
        }
    }
}
#[test]
fn discovers_real_machine_geometry_without_fixed_device_addresses() {
    let p = dtb::parse(GOOD).unwrap();
    assert_eq!(p.ram.size, 256 * 1024 * 1024);
    assert_eq!(p.hart, 0);
    assert_eq!(p.timebase, 10_000_000);
    assert_eq!(p.uart.irq, 10);
    assert_eq!(p.plic_context, 1);
    assert_eq!(p.virtio_count, 8);
}
#[test]
fn incomplete_blob_and_out_of_bounds_strings_are_rejected() {
    for length in [0, 39, 40, GOOD.len() - 1] {
        assert!(dtb::parse(&GOOD[..length]).is_err());
    }
    let mut bad = GOOD.to_vec();
    bad[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(dtb::parse(&bad), Err(Error::Bounds)));
}
#[test]
fn zero_timebase_is_rejected_before_deadlines_exist() {
    let mut bad = GOOD.to_vec();
    let (at, n) = property(&bad, b"timebase-frequency", None);
    assert_eq!(n, 4);
    bad[at..at + 4].fill(0);
    assert!(matches!(dtb::parse(&bad), Err(Error::Missing)));
}
#[test]
fn unknown_interrupt_parent_is_not_a_device_binding() {
    let mut bad = GOOD.to_vec();
    let (at, n) = property(&bad, b"interrupt-parent", Some(b"serial@10000000"));
    assert_eq!(n, 4);
    bad[at..at + 4].copy_from_slice(&0x7777u32.to_be_bytes());
    assert!(dtb::parse(&bad).is_err());
}
