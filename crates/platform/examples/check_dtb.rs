fn main() {
    let path = std::env::args().nth(1).expect("DTB path");
    let bytes = std::fs::read(path).expect("read DTB");
    println!(
        "{:#?}",
        kernel_platform::dtb::parse(&bytes).expect("supported bounded DTB")
    );
}
