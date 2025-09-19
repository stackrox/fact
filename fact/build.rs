use std::{path::PathBuf, process::Command};

use anyhow::{bail, Context};

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=../.git/HEAD");
    let out_dir: PathBuf = std::env::var("OUT_DIR")
        .context("Failed to interpret OUT_DIR environment variable")?
        .into();
    let cmd = Command::new("make")
        .args(["-sC", "..", "version"])
        .output()?;

    if !cmd.status.success() {
        eprintln!("Captured stdout: {}", String::from_utf8_lossy(&cmd.stdout));
        eprintln!("Captured stderr: {}", String::from_utf8_lossy(&cmd.stderr));
        bail!("Failed to run `make version`: {:?}", cmd.status.code());
    }

    let version = String::from_utf8(cmd.stdout)?;
    let out_path = out_dir.join("version.rs");
    std::fs::write(
        &out_path,
        format!(r#"pub const FACT_VERSION: &str = "{}";"#, version.trim()),
    )?;
    Ok(())
}
