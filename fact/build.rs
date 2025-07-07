use std::{env, path::PathBuf, process::Command};

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=../fact-ebpf/");
    let out_dir: PathBuf = env::var("OUT_DIR")?.into();
    let obj = out_dir
        .join("main.o")
        .into_os_string()
        .into_string()
        .unwrap();
    let ec = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-c",
            "../fact-ebpf/main.c",
            "-o",
            &obj,
        ])
        .status()?;
    if ec.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Failed to compile '{ec}'"))
    }
}
