use std::{
    fs::{remove_file, File},
    io::Write,
};

fn main() {
    let exe_path = std::env::current_exe().expect("Failed to get executable path");
    println!("Removing executable: {}", exe_path.display());
    remove_file(exe_path).expect("Failed to remove executable");

    let mut args = std::env::args();
    let path = args.nth(1).expect("File to modify not provided");

    println!("Opening file: {path}");
    let mut f = File::create(path).expect("Failed to create test file");
    f.write_all(b"This is a test")
        .expect("Failed to write to test file");
}
