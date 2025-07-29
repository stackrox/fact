use std::fs::read_to_string;

use anyhow::{bail, Context};

use crate::host_info::get_host_mount;

fn have_bpf_lsm() -> anyhow::Result<()> {
    let lsm_config = get_host_mount().join("sys/kernel/security/lsm");
    let lsm_config = read_to_string(lsm_config).context("Failed to read LSM configuration")?;
    if !lsm_config.split(',').any(|cap| cap == "bpf") {
        bail!("BPF capability for LSM is not configured")
    }
    Ok(())
}

pub fn pre_flight() -> anyhow::Result<()> {
    have_bpf_lsm()
}
