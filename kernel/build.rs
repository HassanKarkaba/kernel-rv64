fn main() {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    println!("cargo:rustc-link-arg=-T{root}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=KERNEL_INIT_ELF");
    let init = std::env::var("KERNEL_INIT_ELF")
        .unwrap_or_else(|_| format!("{root}/../target/riscv64imac-unknown-none-elf/release/init"));
    println!("cargo:rerun-if-changed={init}");
    println!("cargo:rustc-env=KERNEL_INIT_ELF={init}");
}
