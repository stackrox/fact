use anyhow::Context;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn compile_bpf(out_dir: &Path) -> anyhow::Result<()> {
    let obj = match out_dir.join("main.o").into_os_string().into_string() {
        Ok(s) => s,
        Err(os_string) => anyhow::bail!("Failed to convert path to string {:?}", os_string),
    };

    let target_arch = format!("-D__TARGET_ARCH_{}", env::var("CARGO_CFG_TARGET_ARCH")?);

    match Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-c",
            "-Wall",
            "-Werror",
            &target_arch,
            "src/bpf/main.c",
            "-o",
            &obj,
        ])
        .status()
    {
        Ok(status) => {
            if !status.success() {
                anyhow::bail!("Failed to compile eBPF. See stderr for details.");
            }
        }
        Err(e) => anyhow::bail!("Failed to execute clang: {}", e),
    }
    Ok(())
}

fn generate_bindings(out_dir: &Path) -> anyhow::Result<()> {
    let bindings = bindgen::Builder::default()
        .header("src/bpf/types.h")
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .context("Failed to generate bindings")?;
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .context("Failed to write bindings")
}

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=src/bpf/");
    let out_dir: PathBuf = env::var("OUT_DIR")
        .context("Failed to interpret OUT_DIR environment variable")?
        .into();
    compile_bpf(&out_dir).context("Failed to compile eBPF")?;
    generate_bindings(&out_dir)
}
