use std::{path::PathBuf, process::Command};

use anyhow::{Context, bail};

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-changed=../.git/HEAD");
    println!("cargo::rerun-if-env-changed=FACT_BUILD_SHA");
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
    let build_sha = std::env::var("FACT_BUILD_SHA").unwrap_or_else(|_| "unknown".to_owned());
    let out_path = out_dir.join("version.rs");
    std::fs::write(
        &out_path,
        format!(
            "pub const FACT_VERSION: &str = {:?};\npub const FACT_BUILD_SHA: &str = {:?};",
            version.trim(),
            build_sha.trim()
        ),
    )?;
    Ok(())
}
