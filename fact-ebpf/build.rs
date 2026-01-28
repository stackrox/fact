use anyhow::Context;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn compile_bpf(out_dir: &Path) -> anyhow::Result<()> {
    let target_arch = format!("-D__TARGET_ARCH_{}", env::var("CARGO_CFG_TARGET_ARCH")?);

    // Get path to vendored libbpf headers
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let libbpf_include = format!("-I{}/../../third_party/libbpf/src", manifest_dir);

    let base_args = [
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-c",
        "-Wall",
        "-Werror",
        &target_arch,
        &libbpf_include,
    ];

    for name in ["main", "checks"] {
        let obj = match out_dir
            .join(format!("{name}.o"))
            .into_os_string()
            .into_string()
        {
            Ok(s) => s,
            Err(os_string) => anyhow::bail!("Failed to convert path to string {:?}", os_string),
        };

        match Command::new("clang")
            .args(base_args)
            .arg(format!("src/bpf/{name}.c"))
            .args(["-o", &obj])
            .status()
        {
            Ok(status) => {
                if !status.success() {
                    anyhow::bail!("Failed to compile eBPF. See stderr for details.");
                }
            }
            Err(e) => anyhow::bail!("Failed to execute clang: {}", e),
        }
    }
    Ok(())
}

fn generate_bindings(out_dir: &Path) -> anyhow::Result<()> {
    let bindings = bindgen::Builder::default()
        .header("src/bpf/types.h")
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
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
