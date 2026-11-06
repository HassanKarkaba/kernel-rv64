fn main() {
    for path in std::env::args().skip(1) {
        let image = std::fs::read(&path).expect("read ELF");
        let plan = kernel_core::elf::validate(&image).expect("ELF meets ABI loader contract");
        println!(
            "{path}: entry={:#x} segments={} bytes={}",
            plan.entry,
            plan.count,
            image.len()
        );
    }
}
