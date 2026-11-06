fn main() {
    println!("cargo:rerun-if-env-changed=KERNEL_BENCH_KIND");
    let kind = std::env::var("KERNEL_BENCH_KIND").unwrap_or_else(|_| "fairness".to_owned());
    assert!(matches!(
        kind.as_str(),
        "fairness" | "wakeup" | "context" | "masking" | "reclaim"
    ));
    println!("cargo:rustc-env=KERNEL_BENCH_KIND={kind}");
    println!("cargo:rerun-if-env-changed=KERNEL_DEVICE_FAULT");
    let fault = std::env::var("KERNEL_DEVICE_FAULT").unwrap_or_else(|_| "1".to_owned());
    assert!(matches!(
        fault.as_str(),
        "1" | "2" | "3" | "4" | "5" | "6" | "7"
    ));
    println!("cargo:rustc-env=KERNEL_DEVICE_FAULT={fault}");
    let directory = std::env::var("CARGO_MANIFEST_DIR").expect("manifest directory");
    println!("cargo:rustc-link-arg=-T{directory}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=KERNEL_TEST_RUN_ID");
    println!("cargo:rerun-if-env-changed=KERNEL_TEST_BOOT_ID");
    println!("cargo:rerun-if-env-changed=KERNEL_BENCH_PROCESSES");
    let processes = std::env::var("KERNEL_BENCH_PROCESSES").unwrap_or_else(|_| "4".to_owned());
    assert!(
        matches!(processes.as_str(), "4" | "8"),
        "benchmark supports exactly four or eight workers"
    );
    println!("cargo:rustc-env=KERNEL_BENCH_PROCESSES={processes}");
    let run = std::env::var("KERNEL_TEST_RUN_ID").unwrap_or_else(|_| "0".repeat(32));
    let boot = std::env::var("KERNEL_TEST_BOOT_ID").unwrap_or_else(|_| run.clone());
    for (name, value) in [("KERNEL_TEST_RUN_ID", run), ("KERNEL_TEST_BOOT_ID", boot)] {
        assert!(
            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "test identities must be exactly 32 ASCII hexadecimal bytes"
        );
        println!("cargo:rustc-env={name}={value}");
    }
}
