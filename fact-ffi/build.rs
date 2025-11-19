fn main() {
    println!("cargo::rerun-if-changed=src/c/");
    cc::Build::new()
        .file("src/c/inode.c")
        .opt_level(2)
        .warnings_into_errors(true)
        .warnings(true)
        .compile("inode");
}
