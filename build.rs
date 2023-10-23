use cc::Build;

fn main() {
    println!("cargo:rerun-if-changed=src");
    Build::new()
        .file("src/windows.cc")
        .compile("get_last_bootup_time");
}
